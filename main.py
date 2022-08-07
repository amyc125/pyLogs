import codecs
import os
import json
import sys
import traceback
import win32con
import win32evtlog
import win32evtlogutil
import winerror
import uuid
import inquirer
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
from datetime import date

cred = credentials.Certificate("./service-account-file.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

questions = [
    inquirer.Checkbox('choices',
                      message="What Windows event log categories to send?",
                      choices=["All", "System", "Application", "Security"]),

    inquirer.Text('email', message="What's your email address")
]

USERNAME = os.getlogin()
SELECTED_EVENT_CATEGORIES = inquirer.prompt(questions)
EMAIL = SELECTED_EVENT_CATEGORIES['email']

today = date.today()
DATESTAMP = today.strftime("%d-%m-%Y")# convert timestamp to string in dd-mm-yyyy


if "All" in SELECTED_EVENT_CATEGORIES['choices']:
    SELECTED_EVENT_CATEGORIES = ["System", "Application", "Security"]
else:
    SELECTED_EVENT_CATEGORIES = SELECTED_EVENT_CATEGORIES['choices']

with open('./windows_audit_categories.json', 'r') as audit_categories: 
    AUDIT_CATEGORIES = json.load(audit_categories)


#----------------------------------------------------------------------
def handle_users_collection(username, email):
    docs = db.collection(u'users').stream()

    for doc in docs:
        user = doc.to_dict()
        if user['username'] == username:
            return user

    print('new user')
    new_user_data = {"username": username, "email": email}
    db.collection(u'users').document(str(uuid.uuid4())).set(new_user_data)
    return new_user_data


#----------------------------------------------------------------------
def handle_date_collection(datestamp):
    docs = db.collection(u'event_log_collections').stream()

    for doc in docs:
        collection_date = doc.to_dict()
        if collection_date['date'] == datestamp:
            print('date collection already exists')
            return collection_date

    print('new collection date')
    new_collection_data = {"date": datestamp}
    db.collection(u'event_log_collections').document(str(uuid.uuid4())).set(new_collection_data)
    return new_collection_data


#----------------------------------------------------------------------
def getAllEvents(server, logtypes, basePath, username, email):
    if not server:
        serverName = "localhost"
    else: 
        serverName = server
    for logtype in logtypes:
        path = os.path.join(basePath, "%s_%s_log.log" % (serverName, logtype))
        getEventLogs(server, logtype, path, username, email)
#----------------------------------------------------------------------


def enrich_event_log(event_id):
    for category in AUDIT_CATEGORIES:
        if category != "url":
            for log in AUDIT_CATEGORIES[category]:
                if str(log['event_id']) == event_id:
                    print('match found')
                    log['link'] = AUDIT_CATEGORIES['url'] + str(event_id)
                    log['category'] = category
                    return log
    return {
        'category': "unknown",
        'link': 'unknown',
        'info': 'none'
    }
#----------------------------------------------------------------------


def getEventLogs(server, logtype, logPath, username, email):
    """
    Get the event logs from the specified machine according to the
    logtype (Example: system) and save it to the appropriately
    named log file
    """
    print ("Logging %s events" % logtype)
    codecs.open(logPath, encoding='utf-8', mode='w')
    
    hand = win32evtlog.OpenEventLog(server,logtype)
    total = win32evtlog.GetNumberOfEventLogRecords(hand)
    print ("Total events in %s = %s" % (logtype, total))
    print ("\n Logging logs from %s \n" % (logtype))
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand,flags,0)

    #This dict converts the event type into a human readable form
    evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'AUDIT_FAILURE',
              win32con.EVENTLOG_AUDIT_SUCCESS:'AUDIT_SUCCESS',
              win32con.EVENTLOG_INFORMATION_TYPE:'INFORMATION_TYPE',
              win32con.EVENTLOG_WARNING_TYPE:'WARNING_TYPE',
              win32con.EVENTLOG_ERROR_TYPE:'ERROR_TYPE'}

    try:
        events = 1
        while events:
            events=win32evtlog.ReadEventLog(hand,flags,0)
            
            for event_obj in events:

                if not event_obj.EventType in evt_dict.keys():
                    evt_type = "unknown"
                else:
                    evt_type = str(evt_dict[event_obj.EventType])

                enrichment = enrich_event_log(str(winerror.HRESULT_CODE(event_obj.EventID)))
                print(enrichment)

                doc_ref = db.collection(DATESTAMP).document(str(uuid.uuid4()))
                doc_ref.set({
                    'Sid': str(event_obj.Sid),
                    'computer_name': event_obj.ComputerName,
                    'username': username,
                    "logtype": logtype,
                    'event_id': str(winerror.HRESULT_CODE(event_obj.EventID)),
                    'event_type': evt_type,
                    'event_category': event_obj.EventCategory,
                    'source': event_obj.SourceName,
                    'record_number': event_obj.RecordNumber,
                    'message': win32evtlogutil.SafeFormatMessage(event_obj, logtype),
                    'time_generated': event_obj.TimeGenerated.Format(),
                    'audit_category': enrichment['category'],
                    'audit_category_info': enrichment['info'],
                    'external_info': enrichment['link'],
                    'email': email
                })

                time_generated = event_obj.TimeGenerated.Format()
                event_id = str(winerror.HRESULT_CODE(event_obj.EventID))

                print("Event Date/Time: {}".format(time_generated))
                print("Event ID: {}".format(event_id))
                print("Event Type: {}".format(evt_type))

        #closes event log
        win32evtlog.CloseEventLog(hand)

    except:
        print (traceback.print_exc(sys.exc_info()))
#----------------------------------------------------------------------

if __name__ == "__main__":
    server = None  # None = local machine
    handle_users_collection(USERNAME, EMAIL)
    handle_date_collection(DATESTAMP)
    #getAllEvents(server, SELECTED_EVENT_CATEGORIES, ".", USERNAME, EMAIL)
