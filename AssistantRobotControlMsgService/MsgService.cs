using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Reflection;

using LogPrinter;

namespace AssistantRobotControlMsgService
{
    public partial class MsgService : ServiceBase
    {
        protected MsgServiceFunction msf;
        protected bool ifLoadedSuccess = true;
        protected bool ifCloseFromMsgServiceFunction = false;

        public MsgService()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            msf = new MsgServiceFunction(out ifLoadedSuccess);
            if (!ifLoadedSuccess)
            {
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server sevice close at initial pos.");
                Stop();
                return;
            }

            msf.OnSendCloseService += msf_OnSendCloseService;
            msf.StartDoubleListenLoop();
        }

        protected void msf_OnSendCloseService()
        {
            ifCloseFromMsgServiceFunction = true;
            Stop();
        }

        protected override void OnStop()
        {
            if (ifLoadedSuccess && !ifCloseFromMsgServiceFunction)
            {
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server sevice close from outer side.");

                msf.StopDoubleListenLoop().Wait();
                Logger.HistoryPrinting(Logger.Level.INFO, MethodBase.GetCurrentMethod().DeclaringType.FullName, "Msg server sevice ready to closed.");
            }
        }
    }
}
