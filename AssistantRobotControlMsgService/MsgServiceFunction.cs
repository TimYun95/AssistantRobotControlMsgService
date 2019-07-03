using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.IO;
using System.IO.Pipes;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Configuration;

using LogPrinter;

namespace AssistantRobotControlMsgService
{
    public class MsgServiceFunction
    {
        private const byte header1 = 34; // 协议头1
        private const byte header2 = 84; // 协议头2

        #region 枚举 TCP协议
        /// <summary>
        /// TCP协议关键字
        /// </summary>
        public enum TCPProtocol : byte
        {
            Header1 = 0,
            Header2 = 1,
            DeviceID = 2,
            ProtocolKey = 3,
            DataLength = 4,
            DataContent = 8
        }

        /// <summary>
        /// TCP协议关键字 协议关键字
        /// </summary>
        public enum TCPProtocolKey : byte
        {
            RSAPublicKey = 1,
            AESCommonKeyAndIV = 2,
            NormalData = 12,
            EndRemoteControl = 13,
            PingSignal = 14,
            EndBothControl = 21
        }

        /// <summary>
        /// TCP协议关键字 协议关键字 AES公共密钥数据报格式
        /// </summary>
        public enum SecurityKeyLength : int
        {
            AESIVLength = 16,
            AESKeyLength = 32,
            RSAKeyLength = 1024
        }
        #endregion

        #region 字段 TCP
        private readonly bool ifAtSamePC = true;

        private const int clientPortTCPAtSamePC = 40002;
        private const string serverIPAtSamePC = "127.0.0.1";

        private const int clientPortTCPAtDiffPC = 40001;
        private readonly string serverIPAtDiffPC = "192.168.1.13"; // 应该是192.168.1.13

        const int serverPortTCPAny = 40001;

        private Socket tcpListenSocket;
        private CancellationTokenSource tcpListenCancel;
        private Task tcpListenTask;

        private Socket tcpTransferSocket;
        private bool tcpTransferSocketEstablished = false;
        private bool ifTCPTransferEstablished = false;

        private readonly int tcpSocketRecieveTimeOut = 3 * 1000;
        private readonly int tcpSocketSendTimeOut = 1000;
        private System.Timers.Timer tcpBeatClocker;
        private CancellationTokenSource tcpRecieveCancel;
        private Task tcpRecieveTask;

        private byte? remoteDeviceIndex = null;
        private string remoteDevicePublicKey = null;
        const int remoteDevicePublicKeyLength = 1024;

        private byte[] commonKey = null;
        private byte[] commonIV = null;

        private CancellationTokenSource tcpSendCancel;
        private Task tcpSendTask;
        #endregion

        #region 字段 Pipe
        private CancellationTokenSource pipeConnectCancel;
        private Task pipeConnectionTask;

        private NamedPipeServerStream innerPipe;
        private bool ifPipeTransferEstablished = false;
        private readonly string localUIProgramName = "AssistantRobot.exe";
        private readonly string localUIProgramPath = "D:\\";

        private CancellationTokenSource pipeRecieveCancel;
        private Task pipeRecieveTask;

        private CancellationTokenSource pipeSendCancel;
        private Task pipeSendTask;

        #endregion

        #region 关闭事件
        public delegate void SendCloseService();
        public event SendCloseService OnSendCloseService;
        private static readonly object closeSideLocker = new object();
        private bool lockCloseSide = false;
        private bool ifCloseFromInnerSide = true;
        #endregion

        #region 缓冲区
        private Queue<byte[]> pipeToTcpBuffer;
        private Queue<byte[]> tcpToPipeBuffer;
        private readonly int maxBufferSize = 10;
        private static readonly object pipeToTcpBufferLocker = new object();
        private static readonly object tcpToPipeBufferLocker = new object();
        private readonly int waitTimerMsForBuffer = 10;

        /// <summary>
        /// 队列号
        /// </summary>
        protected enum QueueNum : byte { PipeToTcp = 0, TcpToPipe = 1 }
        #endregion

        #region Construct
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="ifSuccessConstructed">是否成功构造</param>
        public MsgServiceFunction(out bool ifSuccessConstructed)
        {
            // 检查环境
            if (!Functions.CheckEnvironment())
            {
                ifSuccessConstructed = false;
                return;
            }
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service starts with successful checked.");

            // 加载程序配置
            bool parseResult = true;

            bool ifAtSamePCTemp;
            parseResult = bool.TryParse(ConfigurationManager.AppSettings["ifAtSamePC"], out ifAtSamePCTemp);
            if (parseResult) ifAtSamePC = ifAtSamePCTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "ifAtSamePC" + ") is wrong.");
                return;
            }

            string serverIPAtDiffPCTemp = ConfigurationManager.AppSettings["serverIPAtDiffPC"];
            if (new string(serverIPAtDiffPCTemp.Take(10).ToArray()) == "192.168.1.") serverIPAtDiffPC = serverIPAtDiffPCTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "serverIPAtDiffPC" + ") is wrong.");
                return;
            }

            int tcpSocketRecieveTimeOutTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["tcpSocketRecieveTimeOut"], out tcpSocketRecieveTimeOutTemp);
            if (parseResult) tcpSocketRecieveTimeOut = tcpSocketRecieveTimeOutTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "tcpSocketRecieveTimeOut" + ") is wrong.");
                return;
            }

            int tcpSocketSendTimeOutTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["tcpSocketSendTimeOut"], out tcpSocketSendTimeOutTemp);
            if (parseResult) tcpSocketSendTimeOut = tcpSocketSendTimeOutTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "tcpSocketSendTimeOut" + ") is wrong.");
                return;
            }

            string localUIProgramNameTemp = ConfigurationManager.AppSettings["localUIProgramName"];
            if (localUIProgramNameTemp == "AssistantRobot.exe") localUIProgramName = localUIProgramNameTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "localUIProgramName" + ") is wrong.");
                return;
            }

            string localUIProgramPathTemp = ConfigurationManager.AppSettings["localUIProgramPath"];
            if (Directory.Exists(localUIProgramPathTemp) && File.Exists(localUIProgramPathTemp + localUIProgramName))
            {
                localUIProgramPath = localUIProgramPathTemp;
            }
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "localUIProgramPath" + ") is wrong.");
                return;
            }

            int maxBufferSizeTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["maxBufferSize"], out maxBufferSizeTemp);
            if (parseResult) maxBufferSize = maxBufferSizeTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "maxBufferSize" + ") is wrong.");
                return;
            }

            int waitTimerMsForBufferTemp;
            parseResult = int.TryParse(ConfigurationManager.AppSettings["waitTimerMsForBuffer"], out waitTimerMsForBufferTemp);
            if (parseResult) waitTimerMsForBuffer = waitTimerMsForBufferTemp;
            else
            {
                ifSuccessConstructed = false;
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "App configuration parameter(" + "waitTimerMsForBuffer" + ") is wrong.");
                return;
            }

            // 创建Pipe通讯管道
            innerPipe = new NamedPipeServerStream("innerCommunication", PipeDirection.InOut, 1, PipeTransmissionMode.Message, PipeOptions.Asynchronous);

            // 装上TCP心跳定时器
            tcpBeatClocker = new System.Timers.Timer(tcpSocketRecieveTimeOut / 2);
            tcpBeatClocker.AutoReset = false;
            tcpBeatClocker.Elapsed += tcpBeatClocker_Elapsed;

            // 缓冲区初始化
            pipeToTcpBuffer = new Queue<byte[]>(maxBufferSize);
            tcpToPipeBuffer = new Queue<byte[]>(maxBufferSize);

            ifSuccessConstructed = true;
        }
        #endregion

        #region Interface
        /// <summary>
        /// 开始双监听循环
        /// </summary>
        public void StartDoubleListenLoop()
        {
            // TCP侦听循环开始
            tcpListenCancel = new CancellationTokenSource();
            tcpListenTask = new Task(() => TcpListenTaskWork(tcpListenCancel.Token));
            tcpListenTask.Start();

            // Pipe等待连接Task开启
            pipeConnectCancel = new CancellationTokenSource();
            pipeConnectionTask = new Task(() => PipeConnectionTaskWork(pipeConnectCancel.Token));
            pipeConnectionTask.Start();
        }

        /// <summary>
        /// 关闭双监听循环
        /// </summary>
        /// <returns>返回监听循环任务</returns>
        public Task StopDoubleListenLoop()
        {
            lock (closeSideLocker)
            {
                lockCloseSide = true;
                ifCloseFromInnerSide = false;
            }
            tcpListenCancel.Cancel(); // 两个连接不再重建
            pipeConnectCancel.Cancel();
            EndTcpOperationWithStopPipeTransfer(); // 关闭TCP同时关闭Pipe
            return pipeConnectionTask;
        }
        #endregion

        #region TCP

        #region TCP 监听
        /// <summary>
        /// TCP监听任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void TcpListenTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp listener begins.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                // 刷新公共密钥
                using (AesCryptoServiceProvider tempAes = new AesCryptoServiceProvider())
                {
                    tempAes.GenerateKey();
                    tempAes.GenerateIV();
                    commonKey = tempAes.Key;
                    commonIV = tempAes.IV;
                }

                // TCP侦听socket建立 开始侦听
                tcpListenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                tcpListenSocket.Bind(new IPEndPoint(IPAddress.Parse(ifAtSamePC ? serverIPAtSamePC : serverIPAtDiffPC), serverPortTCPAny));
                tcpListenSocket.Listen(1);
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp listener begins to listen.");

                // TCP侦听socket等待连接建立
                IAsyncResult acceptResult = tcpListenSocket.BeginAccept(null, null);
                do
                {
                    if (cancelFlag.IsCancellationRequested) break;
                    acceptResult.AsyncWaitHandle.WaitOne(1000, true);  //等待1秒
                } while (!acceptResult.IsCompleted);
                if (cancelFlag.IsCancellationRequested) // 不再accept等待
                {
                    // 清理连接
                    FinishAllTCPConnection();

                    // 清空缓存区
                    lock (pipeToTcpBufferLocker)
                    {
                        pipeToTcpBuffer.Clear();
                    }
                    lock (tcpToPipeBufferLocker)
                    {
                        tcpToPipeBuffer.Clear();
                    }

                    // 清空公钥密钥和设备号
                    remoteDevicePublicKey = null;
                    commonIV = null;
                    commonKey = null;
                    remoteDeviceIndex = null;
                    break;
                }
                tcpTransferSocket = tcpListenSocket.EndAccept(acceptResult);
                tcpTransferSocketEstablished = true;
                tcpTransferSocket.ReceiveTimeout = tcpSocketRecieveTimeOut;
                tcpTransferSocket.SendTimeout = tcpSocketSendTimeOut;
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer connection is established.");

                // TCP连接建立之后关闭侦听socket
                tcpListenSocket.Close();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp listener is closed.");

                // TCP侦听socket关闭后 开始允许TCP传输socket接收数据
                tcpRecieveCancel = new CancellationTokenSource();
                tcpRecieveTask = new Task(() => TcpRecieveTaskWork(tcpRecieveCancel.Token));
                tcpRecieveTask.Start();

                // TCP侦听socket关闭后 开始允许TCP传输socket发送Buffer内数据
                tcpSendCancel = new CancellationTokenSource();
                tcpSendTask = new Task(() => TcpSendTaskWork(tcpSendCancel.Token));
                tcpSendTask.Start();

                // 打开心跳定时器
                tcpBeatClocker.Start();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Beats is required.");

                // 准备连接Pipe通讯
                if (!ifPipeTransferEstablished) // 没连接Pipe则新建连接
                {
                    // 打开本地UI
                    string cmdLine = "lsrunas /user:" + ConfigurationManager.AppSettings["userName"] + " " +
                        "/password:" + ConfigurationManager.AppSettings["userPWD"] + " /domain: " +
                        "/command:" + localUIProgramPath + localUIProgramName + " " +
                        "/runpath:" + localUIProgramPath;
                    SessionUtility.CreateProcess(null, cmdLine);
                   
                    int tempCounter = 0;
                    bool pipeConnectSuccess = true;
                    while (!ifPipeTransferEstablished)
                    {
                        Thread.Sleep(1000); // 等待直到Pipe连接
                        if (++tempCounter > 10) 
                        {
                            pipeConnectSuccess = false;
                            break; // pipe连接超时，tcp重置
                        }
                    }
                    if (!pipeConnectSuccess) NormalEndTcpOperation();
                }

                // 等待直到TCP结束传输数据
                tcpRecieveTask.Wait();
                tcpSendTask.Wait();

                // 准备再次进行TCP监听
                FinishAllTCPConnection();

                // 等待后继续
                Thread.Sleep(1000);

                // 清空缓存区
                lock (pipeToTcpBufferLocker)
                {
                    pipeToTcpBuffer.Clear();
                }
                lock (tcpToPipeBufferLocker)
                {
                    tcpToPipeBuffer.Clear();
                }

                // 清空公钥密钥和设备号
                remoteDevicePublicKey = null;
                commonIV = null;
                commonKey = null;
                remoteDeviceIndex = null;

                // 等待后继续
                Thread.Sleep(1000);
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp listener stops.");
        }
        #endregion

        #region Tcp 心跳
        /// <summary>
        /// 心跳定时器
        /// </summary>
        private void tcpBeatClocker_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            NormalEndTcpOperation();
            Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer recieve no beats in definite time.");
        }
        #endregion

        #region TCP 接收
        /// <summary>
        /// TCP接收数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void TcpRecieveTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer begins to recieve datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                try
                {
                    byte[] reciveDatas = new byte[1024 + 8]; // 最大长度为RSA公钥加上协议头
                    int actualLength = tcpTransferSocket.Receive(reciveDatas);
                    DealWithTcpTransferRecieveDatas(reciveDatas.Take(actualLength).ToArray());
                }
                catch (SocketException ex)
                {
                    if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.TimedOut)
                    { // 意外中断连接 执行一般中断连接
                        NormalEndTcpOperation();
                        Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer recieve no datas in definite time.");
                    }
                    else
                    { // 两个连接不再重建，关闭TCP同时关闭Pipe
                        EndTcpOperationWithStopPipeTransferAndOverService();
                        Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                    }
                }
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer stops to recieve datas.");
        }

        /// <summary>
        /// 处理TCP接收的数据
        /// </summary>
        /// <param name="datas">所收数据</param>
        private void DealWithTcpTransferRecieveDatas(byte[] datas)
        {
            int dataLength = 0;
            if (datas.Length > 8)
            {
                dataLength = Convert.ToInt32(IPAddress.NetworkToHostOrder(
                             BitConverter.ToInt32(datas, (byte)TCPProtocol.DataLength)));
                if (dataLength != datas.Length - 8) return; // 数据段长度不匹配
            }
            else
            {
                if (datas.Length != 4) return;  // 总长度不匹配
            }

            if (datas[(byte)TCPProtocol.Header1] != header1 ||
                datas[(byte)TCPProtocol.Header2] != header2) return; // 协议头不匹配

            byte deviceIndex = datas[(byte)TCPProtocol.DeviceID]; // 设备号
            TCPProtocolKey protocolKey = (TCPProtocolKey)datas[(byte)TCPProtocol.ProtocolKey]; // 标志位

            if (Object.Equals(remoteDeviceIndex, null) && !protocolKey.Equals(TCPProtocolKey.RSAPublicKey)) return; // 尚未获得设备号 不允许接收RSA公钥以外的消息

            switch (protocolKey)
            {
                case TCPProtocolKey.RSAPublicKey:
                    remoteDeviceIndex = deviceIndex; // RSA传送时发送设备号
                    remoteDevicePublicKey = Encoding.UTF8.GetString(datas, (byte)TCPProtocol.DataContent, dataLength);

                    // 发送AES公钥
                    SendAESKey();

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSAKey saved, AES sent, TCP can be used to transfer.");
                    break;
                case TCPProtocolKey.NormalData:
                    if (remoteDeviceIndex != deviceIndex) return; // 设备号不匹配

                    // 入队等待Pipe发送 
                    PushNormalData(datas.Skip((byte)TCPProtocol.DataContent).ToArray());

                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Data enqueue for pipe.");
                    break;
                case TCPProtocolKey.PingSignal:
                    if (remoteDeviceIndex != deviceIndex) return; // 设备号不匹配

                    tcpBeatClocker.Stop(); // 重开计时器
                    tcpBeatClocker.Start();
                    break;
                case TCPProtocolKey.EndRemoteControl:
                    if (remoteDeviceIndex != deviceIndex) return; // 设备号不匹配

                    NormalEndTcpOperation(); // 收到指令进行一般TCP中断操作
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "TCP transfer is stopped.");
                    break;
                case TCPProtocolKey.EndBothControl:
                    if (remoteDeviceIndex != deviceIndex) return; // 设备号不匹配

                    EndTcpOperationWithStopPipeTransfer(); // 收到指令中断TCP操作，同时停止Pipe传输
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "TCP transfer is stopped and cut down pipe transfer at the same time.");
                    break;
                case TCPProtocolKey.AESCommonKeyAndIV:
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Should not appear this command.");
                    break;
                default:
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "No such control command.");
                    break;
            }
        }

        /// <summary>
        /// 发送AES密钥
        /// </summary>
        private void SendAESKey()
        {
            List<byte> aesKey = new List<byte>((int)SecurityKeyLength.AESIVLength + (int)SecurityKeyLength.AESKeyLength);
            aesKey.AddRange(commonIV);
            aesKey.AddRange(commonKey);
            byte[] keyDatas = EncryptByRSA(aesKey.ToArray()); // 加密数据内容

            if (!Object.Equals(keyDatas, null))
            {
                byte[] sendDatas = EnpackTCP(keyDatas, TCPProtocolKey.AESCommonKeyAndIV);
                SendWork(sendDatas);
                ifTCPTransferEstablished = true;
            }
        }

        /// <summary>
        /// 一般消息数据入队
        /// </summary>
        /// <param name="rawBytes">原始数据内容</param>
        private void PushNormalData(byte[] rawBytes)
        {
            byte[] datas = DecryptByAES(rawBytes); // 解密
            if (!Object.Equals(datas, null)) PushToQueue(datas, QueueNum.TcpToPipe);
        }
        #endregion

        #region TCP 发送
        /// <summary>
        /// TCP发送数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void TcpSendTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer is ready to send datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                byte[] dataContent = PopFromQueue(QueueNum.PipeToTcp);
                if (Object.Equals(dataContent, null))
                {
                    Thread.Sleep(waitTimerMsForBuffer);
                    continue;
                }

                SendTCPBytes(dataContent);
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer stops to send datas.");
        }

        /// <summary>
        /// TCP加密、打包并发送数据
        /// </summary>
        /// <param name="dataContent">原始数据内容</param>
        private void SendTCPBytes(byte[] dataContent)
        {
            byte[] encryptedContent = EncryptByAES(dataContent); // 加密

            if (Object.Equals(encryptedContent, null)) return; // 加密失败

            byte[] sendBytes = EnpackTCP(encryptedContent, TCPProtocolKey.NormalData); // 打包

            SendWork(sendBytes); // 发送
        }

        /// <summary>
        /// TCP协议打包数据
        /// </summary>
        /// <param name="dataContent">待打包的数据</param>
        /// <param name="functionalNum">功能码</param>
        /// <returns>打包后的数据</returns>
        private byte[] EnpackTCP(byte[] dataContent, TCPProtocolKey functionalNum)
        {
            List<byte> sendBytes = new List<byte>(8 + dataContent.Length);
            sendBytes.Add(header1);
            sendBytes.Add(header2);
            sendBytes.Add(remoteDeviceIndex.HasValue ? remoteDeviceIndex.Value : byte.MinValue);
            sendBytes.Add((byte)functionalNum);
            sendBytes.AddRange(BitConverter.GetBytes(IPAddress.HostToNetworkOrder(dataContent.Length)));
            sendBytes.AddRange(dataContent);

            return sendBytes.ToArray();
        }

        /// <summary>
        /// TCP发送数据
        /// </summary>
        /// <param name="sendBytes">待发送的数据</param>
        private void SendWork(byte[] sendBytes)
        {
            try
            {
                tcpTransferSocket.Send(sendBytes);
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.ConnectionReset || ex.SocketErrorCode == SocketError.ConnectionAborted || ex.SocketErrorCode == SocketError.TimedOut)
                { // 意外中断连接 执行一般中断连接
                    NormalEndTcpOperation();
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service tcp transfer send datas failed.", ex);
                }
                else
                { // 两个连接不再重建，关闭TCP同时关闭Pipe
                    EndTcpOperationWithStopPipeTransferAndOverService();
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                }
            }
        }
        #endregion

        #endregion

        #region Pipe

        #region 枚举 Pipe通讯
        /// <summary>
        /// 应用协议总体格式
        /// </summary>
        public enum AppProtocol : byte
        {
            DataLength = 0,
            DataFlow = 4,
            DataKey = 5,
            DataContent = 6
        }

        /// <summary>
        /// 应用协议数据流向
        /// </summary>
        public enum AppProtocolDireciton : byte
        {
            Local2Remote = 9,
            Remote2Local = 219
        }

        /// <summary>
        /// 应用协议状态
        /// </summary>
        public enum AppProtocolStatus : byte
        {
            URRealTimeData = 1,
            URNetAbnormalAbort = 2,
            URWorkEmergencyState = 3,
            URNearSingularState = 4,
            URInitialPowerOnAsk = 5,
            URInitialPowerOnAskReply = 6,

            BreastScanConfiguration = 101,
            BreastScanWorkStatus = 102,
            BreastScanConfigurationConfirmStatus = 103,
            BreastScanForceZerodStatus = 104,
            BreastScanConfigurationProcess = 151,
            BreastScanImmediateStop = 201,
            BreastScanImmediateStopRecovery = 202,

            EndPipeConnection = 251
        }
        #endregion

        #region Pipe 连接
        /// <summary>
        /// Pipe连接任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void PipeConnectionTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe connector begins.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                // 等待本地UI连接
                IAsyncResult connectResult = innerPipe.BeginWaitForConnection(null, null);
                do
                {
                    if (cancelFlag.IsCancellationRequested) break;
                    connectResult.AsyncWaitHandle.WaitOne(1000, true);  //等待1秒
                } while (!connectResult.IsCompleted);
                if (cancelFlag.IsCancellationRequested) // 不再connect等待
                {
                    // Pipe连接终止标志位
                    ifPipeTransferEstablished = false;
                    break;
                }
                innerPipe.EndWaitForConnection(connectResult);

                // Pipe连接建立之后允许Pipe接收数据
                pipeRecieveCancel = new CancellationTokenSource();
                pipeRecieveTask = new Task(() => PipeRecieveTaskWork(pipeRecieveCancel.Token));
                pipeRecieveTask.Start();

                // Pipe连接建立之后允许Pipe发送数据
                pipeSendCancel = new CancellationTokenSource();
                pipeSendTask = new Task(() => PipeSendTaskWork(pipeSendCancel.Token));
                pipeSendTask.Start();

                // Pipe连接建立标志位
                ifPipeTransferEstablished = true;

                // 等待直到Pipe结束接收数据
                pipeSendTask.Wait();
                pipeRecieveTask.Wait();

                // Pipe连接终止标志位
                ifPipeTransferEstablished = false;

                // 断开Pipe连接
                innerPipe.Disconnect();

                // 等待后继续
                Thread.Sleep(2000);
            }

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe connector stops.");

            tcpListenTask.Wait();
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe connector stops with tcp listener stops too.");

            if (ifCloseFromInnerSide)
            {
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service close from inner side.");
                OnSendCloseService();
            }
        }
        #endregion

        #region Pipe 发送
        /// <summary>
        /// Pipe发送数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void PipeSendTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe transfer begins to send datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                byte[] pipeDatas = PopFromQueue(QueueNum.TcpToPipe);
                if (Object.Equals(pipeDatas, null))
                {
                    Thread.Sleep(waitTimerMsForBuffer);
                    continue;
                }

                try
                {
                    innerPipe.Write(pipeDatas, 0, pipeDatas.Length);
                    innerPipe.Flush();
                }
                catch (Exception ex)
                { // 两个连接不再重建，关闭TCP同时关闭Pipe
                    EndTcpOperationWithStopPipeTransferAndOverService();
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                }
            }

            pipeRecieveCancel.Cancel(); // 发送停止，则接收也准备停止

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe transfer stops to send datas.");
        }
        #endregion

        #region Pipe 接收
        /// <summary>
        /// Pipe接收数据任务
        /// </summary>
        /// <param name="cancelFlag">停止标志</param>
        private void PipeRecieveTaskWork(CancellationToken cancelFlag)
        {
            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe transfer begins to recieve datas.");

            while (true)
            {
                if (cancelFlag.IsCancellationRequested) break;

                try
                {
                    byte[] recieveBuf = new byte[150];
                    int recieveLength = innerPipe.Read(recieveBuf, 0, 150);

                    // 长度为0，则连接中断
                    if (recieveLength < 1) throw new Exception("Pipe should not be cut down, but recieve 0 byte.");

                    // 获取数据
                    byte[] recieveDatas = recieveBuf.Take(recieveLength).ToArray();

                    // 判断是否收到关闭Pipe连接的指令
                    if (recieveLength == 6 &&
                        Convert.ToInt32(
                        IPAddress.NetworkToHostOrder(
                        BitConverter.ToInt32(recieveDatas,
                                                            (byte)AppProtocol.DataLength))) == 6 - 4 &&
                        recieveDatas[(byte)AppProtocol.DataFlow] == (byte)AppProtocolDireciton.Local2Remote &&
                        recieveDatas[(byte)AppProtocol.DataKey] == (byte)AppProtocolStatus.EndPipeConnection)
                    {
                        EndTcpOperationWithStopPipeTransfer();
                    }
                    else // 不是中断Pipe连接指令，则入队
                    {
                        PushToQueue(recieveDatas, QueueNum.PipeToTcp);
                    }
                }
                catch (SocketException ex)
                { // 两个连接不再重建，关闭TCP同时关闭Pipe
                    EndTcpOperationWithStopPipeTransferAndOverService();
                    Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Not deal exception.", ex);
                }
            }

            // Pipe接收停止，则发送一定停止，Pipe连接中断

            Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server service pipe transfer stops to recieve datas.");
        }
        #endregion

        #endregion

        #region Queue 操作
        /// <summary>
        /// 入队操作
        /// </summary>
        /// <param name="pushData">入队数据</param>
        /// <param name="queueNum">队列号</param>
        /// <param name="enforcedPush">强制入队</param>
        private void PushToQueue(byte[] pushData, QueueNum queueNum, bool enforcedPush = false)
        {
            switch (queueNum)
            {
                case QueueNum.PipeToTcp:
                    if (!ifTCPTransferEstablished && !enforcedPush) return; // 传输不被允许，而且也不强制入队
                    lock (pipeToTcpBufferLocker)
                    {
                        if (pipeToTcpBuffer.Count < maxBufferSize) pipeToTcpBuffer.Enqueue(pushData);
                        else Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "PipeToTcpBuffer queue is full.");
                    }
                    break;
                case QueueNum.TcpToPipe:
                    if (!ifPipeTransferEstablished && !enforcedPush) return; // 传输不被允许，而且也不强制入队
                    lock (tcpToPipeBufferLocker)
                    {
                        if (tcpToPipeBuffer.Count < maxBufferSize) tcpToPipeBuffer.Enqueue(pushData);
                        else Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "TcpToPipeBuffer queue is full.");
                    }
                    break;
                default:
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "No such queue exists, number: " + ((byte)queueNum).ToString() + ".");
                    break;
            }
        }

        /// <summary>
        /// 出队操作
        /// </summary>
        /// <param name="queueNum">队列号</param>
        /// <returns>返回队首元素</returns>
        private byte[] PopFromQueue(QueueNum queueNum)
        {
            switch (queueNum)
            {
                case QueueNum.PipeToTcp:
                    lock (pipeToTcpBufferLocker)
                    {
                        if (pipeToTcpBuffer.Count < 1) return null; // 空队列
                        return pipeToTcpBuffer.Dequeue();
                    }
                case QueueNum.TcpToPipe:
                    lock (tcpToPipeBufferLocker)
                    {
                        if (tcpToPipeBuffer.Count < 1) return null; // 空队列
                        return tcpToPipeBuffer.Dequeue();
                    }
                default:
                    Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "No such queue exists, number: " + ((byte)queueNum).ToString() + ".");
                    return null;
            }
        }
        #endregion

        #region 加解密
        /// <summary>
        /// RSA公钥加密数据
        /// </summary>
        /// <param name="nonEncryptedBytes">待加密字节流</param>
        /// <returns>加密后的字节流</returns>
        private byte[] EncryptByRSA(byte[] nonEncryptedBytes)
        {
            if (Object.Equals(nonEncryptedBytes, null) || nonEncryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for encrypting by RSA is abnormal.");
                return null; // 待加密数据异常
            }
            if (Object.Equals(remoteDevicePublicKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "RSA public key has not been known yet.");
                return null; // RSA公钥未知
            }

            byte[] encryptedBytes = null;
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(remoteDevicePublicKey);
                if (nonEncryptedBytes.Length > ((int)SecurityKeyLength.RSAKeyLength) / 8 - 11) return null; // 待加密数据过长

                encryptedBytes = rsa.Encrypt(nonEncryptedBytes, false);
            }
            return encryptedBytes;
        }

        /// <summary>
        /// AES加密数据
        /// </summary>
        /// <param name="nonEncryptedBytes">待加密字节流</param>
        /// <returns>加密后的字节流</returns>
        private byte[] EncryptByAES(byte[] nonEncryptedBytes)
        {
            if (Object.Equals(nonEncryptedBytes, null) || nonEncryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for encrypting by AES is abnormal.");
                return null; // 待加密数据异常
            }
            if (Object.Equals(commonIV, null) ||
                Object.Equals(commonKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AES key has not been known yet.");
                return null; // AES密钥和初始向量未知
            }

            string nonEncryptedString = Encoding.UTF8.GetString(nonEncryptedBytes);

            byte[] encryptedBytes = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = commonKey; aes.IV = commonIV;
                ICryptoTransform encryptorByAES = aes.CreateEncryptor();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptorByAES, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(nonEncryptedString);
                        }
                        encryptedBytes = msEncrypt.ToArray();
                    }
                }
            }
            return encryptedBytes;
        }

        /// <summary>
        /// AES解密数据
        /// </summary>
        /// <param name="encryptedBytes">待解密字节流</param>
        /// <returns>解密后的字节流</returns>
        private byte[] DecryptByAES(byte[] encryptedBytes)
        {
            if (Object.Equals(encryptedBytes, null) || encryptedBytes.Length < 1)
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Datas for decrypting by AES is abnormal.");
                return null; // 待解密数据异常
            }
            if (Object.Equals(commonIV, null) ||
                Object.Equals(commonKey, null))
            {
                Logger.HistoryPrinting(Logger.Level.WARN, MethodBase.GetCurrentMethod().DeclaringType.FullName, "AES key has not been known yet.");
                return null; // AES密钥和初始向量未知
            }

            byte[] decryptedBytes = null;
            using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider())
            {
                aes.Key = commonKey; aes.IV = commonIV;
                ICryptoTransform decryptorByAES = aes.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptorByAES, CryptoStreamMode.Read))
                    {
                        using (StreamReader swDecrypt = new StreamReader(csDecrypt))
                        {
                            string decryptedString = swDecrypt.ReadToEnd();
                            decryptedBytes = Encoding.UTF8.GetBytes(decryptedString);
                        }
                    }
                }
            }
            return decryptedBytes;
        }
        #endregion

        #region 中止操作
        /// <summary>
        /// 一般TCP中断连接操作
        /// </summary>
        private void NormalEndTcpOperation()
        {
            ifTCPTransferEstablished = false; // 不再允许TCP传输

            if (!Object.Equals(tcpRecieveCancel, null))
            {
                tcpRecieveCancel.Cancel(); // 停止TCP接收
            }

            tcpBeatClocker.Stop(); // 停止TCP心跳计时

            if (!Object.Equals(tcpSendCancel, null))
            {
                tcpSendCancel.Cancel(); // 停止TCP发送
            }
        }

        /// <summary>
        /// TCP中断连接操作，附加停止Pipe传输
        /// </summary>
        private void EndTcpOperationWithStopPipeTransfer()
        {
            NormalEndTcpOperation();

            // 停止Pipe传输，终止Pipe发送
            if (!Object.Equals(pipeSendCancel, null))
            {
                pipeSendCancel.Cancel();
            }
        }

        /// <summary>
        /// TCP中断连接操作，附加停止Pipe传输，并停止重新连接，准备关闭服务
        /// </summary>
        private void EndTcpOperationWithStopPipeTransferAndOverService()
        {
            lock (closeSideLocker)
            {
                if (!lockCloseSide) ifCloseFromInnerSide = true;
            }
            tcpListenCancel.Cancel(); // 两个连接不再重建
            pipeConnectCancel.Cancel();
            EndTcpOperationWithStopPipeTransfer(); // 关闭TCP同时关闭Pipe
        }

        /// <summary>
        /// 结束所有TCP连接
        /// </summary>
        private void FinishAllTCPConnection()
        {
            if (tcpTransferSocketEstablished)
            {
                tcpTransferSocket.Shutdown(SocketShutdown.Both);
                tcpTransferSocket.Close();
                tcpTransferSocketEstablished = false;
            }
        }
        #endregion
    }
}
