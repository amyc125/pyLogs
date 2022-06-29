import codecs
import os
import json
import win32security
import sys
import time
import traceback
import win32con
import win32evtlog
import win32evtlogutil
import winerror
import uuid
from datetime import date

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

cred = credentials.Certificate("./service-account-file.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

today = date.today()
# convert timestamp to string in dd-mm-yyyy
datestamp = today.strftime("%d-%m-%Y")

uuid = str(uuid.uuid4())
#----------------------------------------------------------------------
def getAllEvents(server, logtypes, basePath):
    if not server:
        serverName = "localhost"
    else: 
        serverName = server
    for logtype in logtypes:
        path = os.path.join(basePath, "%s_%s_log.log" % (serverName, logtype))
        getEventLogs(server, logtype, path)

#----------------------------------------------------------------------
def get_sid():

    desc = win32security.GetFileSecurity(
        ".", win32security.OWNER_SECURITY_INFORMATION
    )
    sid = desc.GetSecurityDescriptorOwner()

    sidstr = win32security.ConvertSidToStringSid(sid)
    return sidstr
#----------------------------------------------------------------------

def getEventLogs(server, logtype, logPath):
    """
    Get the event logs from the specified machine according to the
    logtype (Example: Application) and save it to the appropriately
    named log file
    """
    # print ("Logging %s events" % logtype)
    log = codecs.open(logPath, encoding='utf-8', mode='w')
    # line_break = '-' * 80
    
    log.write("\n%s Log of %s Events\n" % (server, logtype))
    
    # log.write("Created: %s\n\n" % time.ctime())
    # log.write("\n" + line_break + "\n")
    hand = win32evtlog.OpenEventLog(server,logtype)

    #total = win32evtlog.GetNumberOfEventLogRecords(hand)

    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand,flags,0)

    #This dict converts the event type into a human readable form
    evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'EVENTLOG_AUDIT_FAILURE',
              win32con.EVENTLOG_AUDIT_SUCCESS:'EVENTLOG_AUDIT_SUCCESS',
              win32con.EVENTLOG_INFORMATION_TYPE:'EVENTLOG_INFORMATION_TYPE',
              win32con.EVENTLOG_WARNING_TYPE:'EVENTLOG_WARNING_TYPE',
              win32con.EVENTLOG_ERROR_TYPE:'EVENTLOG_ERROR_TYPE'}


    try:
        events=1

        while events:
            events=win32evtlog.ReadEventLog(hand,flags,0)
        
            for event_obj in events:
                if not event_obj.EventType in evt_dict.keys():
                    evt_type = "unknown"
                else:
                    evt_type = str(evt_dict[event_obj.EventType])
                event_json_obj = {
                }

                print(event_json_obj)
                
                doc_ref = db.collection(datestamp).document(uuid)
                doc_ref.set({
                    'Sid': str(event_obj.Sid),
                    'computer_name': event_obj.ComputerName,
                    'event_id': str(winerror.HRESULT_CODE(event_obj.EventID)),
                    'event_type': evt_type,
                    'event_category': event_obj.EventCategory,
                    'source': event_obj.SourceName,
                    'record_number': event_obj.RecordNumber,
                    'message': win32evtlogutil.SafeFormatMessage(event_obj, logtype),
                    'time_generated': event_obj.TimeGenerated.Format(),
                })

    except:
        print (traceback.print_exc(sys.exc_info()))

if __name__ == "__main__":
    server = None  # None = local machine
    logTypes = ["System", "Application", "Security"]
    getAllEvents(server, logTypes, ".")