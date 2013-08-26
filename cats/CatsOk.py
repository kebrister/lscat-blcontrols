#! /usr/local/bin/python
#
#
# Support for data collection at LS-CAT
#
# Copyright 2008-2013 by Keith Brister, Northwestern University
#
#   This file is part of the LS-CAT Beamline Control Package which is
#   free software: you can redistribute it and/or modify it under the
#   terms of the GNU General Public License as published by the Free
#   Software Foundation, either version 3 of the License, or (at your
#   option) any later version.
#
#   This software is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
#
#
# Support for CATS robot control
#
#


import sys, os, select, pg, time, traceback, datetime, socket



class CatsOkError( Exception):
    value = None

    def __init__( self, value):
        self.value = value
        print >> sys.stderr, sys.exc_info()[0]
        print >> sys.stderr, '-'*60
        traceback.print_exc(file=sys.stderr)
        print >> sys.stderr, '-'*60

    def __str__( self):
        return repr( self.value)


class _Q:
    
    db = None   # our database connection

    def open( self):
        self.db = pg.connect( dbname="ls", host="contrabass.ls-cat.org", user="lsuser" )

    def close( self):
        self.db.close()

    def __init__( self):
        self.open()

    def reset( self):
        self.db.reset()

    def query( self, qs):
        if qs == '':
            return rtn
        if self.db.status == 0:
            self.reset()
        try:
            # ping the server
            qr = self.db.query(qs)
        except:
            print "Failed query: %s" % (qs)
            if self.db.status == 1:
                print >> sys.stderr, sys.exc_info()[0]
                print >> sys.stderr, '-'*60
                traceback.print_exc(file=sys.stderr)
                print >> sys.stderr, '-'*60
                return None
            # reset the connection, should
            # put in logic here to deal with transactions
            # as transactions are rolled back
            #
            self.db.reset()
            if self.db.status != 1:
                # Bad status even after a reset, bail
                raise CatsOkError( 'Database Connection Lost')

            qr = self.db.query( qs)

        return qr

    def dictresult( self, qr):
        return qr.dictresult()

    def e( self, s):
        return pg.escape_string( s)

    def fileno( self):
        return self.db.fileno()

    def getnotify( self):
        return self.db.getnotify()

class CatsOk:
    """
    Monitors status of the cats robot, updates database, and controls CatsOk lock
    """
    oldStr = None       # used to keep from spamming console
    oldSendCmd = None
    oldPushCmd = None
    inRecoveryMode = False
    workingPath = ""    # path we are currently running
    pathsNeedingAirRights = [
        "put", "put_bcrd", "get", "getput", "getput_bcrd", "test"
        ]

    sampleMounted = { "lid" : None, "sample" : None, "timestamp" : None}
    sampleTooled  = { "lid" : None, "sample" : None, "timestamp" : None}
    checkMountedSample = False

    dbFlag       = True        # indicates a command might still be in the queue
    lastPathName  = ""
    cryoLocked = None
    needAirRights = False
    haveAirRights = False
    catsExclusionZone = None
    dpX = None
    dpY = None
    dpZ = None
    inExclusionZone = False

    robotOn = None
    robotInRemote = None
    robotError = None
    diES       = None

    termstr = "\r"      # character expected to terminate cats response
    db = None           # database connection

    t1 = None           # socket object used to make connection to cats control socket
    t1Input = ""        # used to build response from t1

    t2 = None           # socket object used to make connection to cats status socket
    t2Input = ""        # used to build response from t2

    p = None            # poll object to manage active file descriptors

    fan = {}            # Dictionary used to find the appropriate service routine for each socket

    sFan = {}           # Dictionary used to parse status socket messages

    MD2 = None          # Sphere Defining MD2 location exclusion zone
    RCap = None         # Capsule defining robot tool and arm
    RR   = 0.7          # Distance from tool tip to elbow
    Pr2 = False         # Process Output 2: CATS requires Air Rights

    statusStateLast    = None
    statusIoLast       = None
    statusPositionLast = None
    statusMessageLast  = None
    waiting = False     # true when the last status reponse did not contain an entire message (more to come)
                        #
                        # Command Queues
                        #  There are two queues: cmdQueue and afterCmd
                        #      cmdQueue runs the given command at the specified time
                        #      afterCmd saves path commands (with the start time) until the current path is no longer running
                        #
                        #   If a path is running then new path commands are added to afterCmd
                        #   If a path command is not running or if the command to be added is not a path command then
                        #   the command is added directly to cmdQueue
                        #   This gets around the problem that the CATS will ignore commands that it doesn't like while running a path.
                        #   But allows us to immediately run a command while a path is running if it is likely to be executed.
                        #   This is a long winded explaination.  This allows us to send vdiXX commands while a path is running while queuing up the next getput/get/put
                        #   vdi90 = airrights, so we really need to be able to do this.
                        #
                        #   vdi91 = in diffractometer air space
                        #
    cmdQueue = []       # queue of commands received from postgresql: tuple (cmd,startTime,path,tool)
    afterCmd    = []    # queue of commands to run after the current one is done
    statusQueue = []    # queue of status requests to send to cats server
    statusFailedPushCount = 0


    def maybePushStatus( self, rqst):
        if self.t2 == None:
            # send requests to the bit bucket if the server is not connected
            return False
        try:
            i = self.statusQueue.index( rqst)
        except ValueError:
            self.statusQueue.append( rqst)
            self.p.register( self.t2, select.POLLIN | select.POLLPRI | select.POLLOUT)
            return True

        self.statusFailedPushCount += 1
        if self.statusFailedPushCount >=10:
            print "Exceeded failure count"
            return False
        self.statusFailedPushCount = 0
        return True

    def popStatus( self):
        rtn = None
        if len( self.statusQueue):
            rtn = self.statusQueue.pop()
        else:
            self.p.register( self.t2, select.POLLIN | select.POLLPRI)
        return rtn

    def compareCmdQueue( self, x, y):
        if x[1] < y[1]:
            return -1
        if x[1] > y[1]:
            return 1
        return 0

    def pushCmd( self, cmd, startTime=datetime.datetime.now(), path=None, tool=None):
        if self.oldPushCmd == None or self.oldPushCmd != cmd:
            print "pushing command '%s'" % (cmd)
            self.oldPushCmd = cmd
        if cmd == 'abort' or cmd == 'panic':
            self.cmdQueue = []
            self.afterCmd = []
            startTime = datetime.datetime.now()
        self.cmdQueue.append( (cmd, startTime, path, tool))
        self.cmdQueue.sort( self.compareCmdQueue)
        self.p.register( self.t1, select.POLLIN | select.POLLPRI | select.POLLOUT)


    def nextCmd( self):
        rtn = None
        if len( self.cmdQueue) > 0:
            if self.cmdQueue[0][1] <= datetime.datetime.now():
                if self.cmdQueue[0][2] != None:
                    tool = int(self.cmdQueue[0][3])
                    qs = "select cats.cmdTimingStart( '%s', %d)" % (self.cmdQueue[0][2], tool)
                    self.db.query( qs)
                rtn = self.cmdQueue.pop(0)[0]
        else:
            self.p.register( self.t1, select.POLLIN | select.POLLPRI)

        return rtn

    def dbService( self, event):

        if event & select.POLLERR:
            self.db.reset()

        if event & (select.POLLIN | select.POLLPRI):
            #
            # Eat up any accumulated notifies
            #
            ntfy = self.db.getnotify()
            while  ntfy != None:
                print "Received Notify: ", ntfy
                ntfy = self.db.getnotify()

            #
            # grab a waiting command
            #
            self.dbFlag = True
            while( self.dbFlag):
                qr = self.db.query( "select cmd, startEpoch as se, pqpath, pqtool from cats._popqueue()")
                r = qr.dictresult()[0]
                if len( r["cmd"]) > 0:
                    cmd = r["cmd"]
                    path = r["pqpath"]
                    tool = r["pqtool"]
                    startTime = datetime.datetime.fromtimestamp(r["se"])
                    print r["se"], startTime
                    d = startTime - datetime.datetime.now()
                    print "Got command %s to be started in %d seconds" % (cmd, d.days*86400+d.seconds+d.microseconds/1000000)
                else:
                    if self.workingPath == "" and len(self.afterCmd) > 0:
                        print "Queuing Command: ", self.afterCmd[0][0]
                        self.pushCmd( self.afterCmd[0][0], self.afterCmd[0][1], self.afterCmd[0][2], self.afterCmd[0][3])
                        self.workingPath = self.afterCmd[0][0]
                        self.afterCmd.pop(0)
                    self.dbFlag = False
                    return True

                #
                # does this look like a normal path command that we might want to delay?
                #
                if cmd.find( "(") > 0:
                    try:
                        # Pick off the path name and test it against those needing air rights:
                        #  We'll need a second list of commands to test if we ever want to call one that does not need air rights
                        ndx = self.pathsNeedingAirRights.index( path)
                    except ValueError:
                        #
                        # No path found: just push the command and hope for the best
                        self.pushCmd( cmd, startTime, path, tool)
                        self.workingPath = cmd
                    else:
                        #
                        # We found one: save it for later if we are busy now
                        #
                        if self.workingPath != "":
                            self.afterCmd.append((cmd, startTime, path, tool))
                            print "Saving Command: ", cmd
                        else:
                            self.pushCmd( cmd, startTime, path, tool)
                            self.workingPath = cmd
                else:
                    self.pushCmd( cmd, startTime, path, tool)
                    self.workingPath = cmd
        return True

    #
    # Service reply from Command socket
    #
    def t1Service( self, event):
        if event & select.POLLOUT:
            cmd = self.nextCmd()
            if cmd != None:
                if self.oldSendCmd == None or self.oldSendCmd != cmd:
                    print "sending command '%s'" % (cmd)
                    self.oldSendCmd = cmd
                self.t1.send( cmd + self.termstr)

        if event & (select.POLLIN | select.POLLPRI):
            newStr = self.t1.recv( 4096)
            if len(newStr) == 0:
                self.p.unregister( self.t1.fileno())
                return False

            if self.oldStr == None or newStr != self.oldStr:
                print "Received:", newStr
                str = self.t1Input + newStr
                pList = str.replace('\n','\r').split( self.termstr)
                if len( str) > 0 and str[-2:-1] != self.termstr:
                    self.t1Input = pList.pop( -1)
        
                for s in pList:
                    print s
                self.oldStr = newStr

        return True

    #
    # Service reply from status socket
    def t2Service( self, event):
        if event & (select.POLLIN | select.POLLPRI):
            try:
                newStr = self.t2.recv( 4096)
            except socket.error:
                self.p.unregister( self.t2.fileno())
                self.t2 = None
                return False

            #
            # zero length return means an error, most likely the socket has shut down
            if len(newStr) == 0:
                self.p.unregister( self.t2.fileno())
                self.t2 = None
                return False

            # Assume we have the full response
            self.waiting = False

            #print "Status Received:", newStr.strip()

            #
            # add what we have from what was left over from last time
            str = self.t2Input + newStr
        
            #
            # split the string into an array of responses: each distinct reply ends with termstr
            pList = str.replace('\n','\r').split( self.termstr)
            if len( str) > 0 and str[-2:-1] != self.termstr:
                # if the last entry does not end with a termstr then there is more to come, save it for later
                #
                self.t2Input = pList.pop( -1)
        
            #
            # go through the list of completed status responses
            for s in pList:
                sFound = False
                for ss in self.sFan:
                    if s.startswith( ss):
                        # call the status response function
                        self.sFan[ss](s)
                        sFound = True
                        break
                if not sFound:
                    # if we do not recognize the response then it must be a message
                    self.statusMessageParse( s)

        if event & select.POLLOUT:
            s = self.popStatus()
            if s != None:
                #print "status request: ", s
                self.t2.send( s + self.termstr)

        return True

    def __init__( self, stn=None):
        # See if we are on a path that requires air rights

        #
        # establish connecitons to database server
        self.db = _Q()

        #
        # establish connections to CATS sockets
        if stn != None:
            qs = "select coalesce(px.getcatsaddr( stn='%s')::text,'Not Found') as a" % stn
        else:
            qs = "select coalesce(px.getcatsaddr()::text,'Not Found') as a"
        qr = self.db.query(qs)
        
        catsaddr = qr.dictresult()[0]["a"]
        if catsaddr == "Not Found":
            raise CatsOkError( "Robot's address not found.  Sorry.")

        self.t1 = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.t1.connect( ( catsaddr, 1000))
        except socket.error:
            raise CatsOkError( "Could not connect to command port")
        self.t1.setblocking( 1)


        self.t2 = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.t2.connect( ( catsaddr, 10000))
        except socket.error:
            raise CatsOkError( "Could not connect to status port")
        self.t2.setblocking( 1)

        #
        # Listen to db requests
        self.db.query( "select cats.init()")

        #
        # Find diffractometer position: assume it does not change while we are running
        #
        qs = "select dpx, dpy, dpz from cats.diffpos where dpstn=px.getstation()"
        qr = self.db.query( qs)
        r = qr.dictresult()[0]
        self.dpX = float(r["dpx"])
        self.dpY = float(r["dpy"])
        self.dpZ = float(r["dpz"])

        #
        # Set up poll object
        self.p = select.poll()
        self.p.register( self.t1.fileno(), select.POLLIN | select.POLLPRI)
        self.p.register( self.t2.fileno(), select.POLLIN | select.POLLPRI)
        self.p.register( self.db.fileno(), select.POLLIN | select.POLLPRI)

        #
        # Set up fan to unmultiplex the poll response
        self.fan = {
            self.t1.fileno()     : self.t1Service,
            self.t2.fileno()     : self.t2Service,
            self.db.fileno()     : self.dbService,
            }

        #
        # Set up sFan to handle status socket messages
        self.sFan = {
            "state("    : self.statusStateParse,
            #"io("       : self.statusIoParse,
            "di("       : self.statusDiParse,
            "do("       : self.statusDoParse,
            "position(" : self.statusPositionParse,
            "config"   : self.statusConfigParse
            }

        self.srqst = {
            "state"     : { "period" : 0.55,   "last" : None, "rqstCnt" : 0, "rcvdCnt" : 0},
            "do"        : { "period" : 0.5,    "last" : None, "rqstCnt" : 0, "rcvdCnt" : 0},
            "di"        : { "period" : 0.6,    "last" : None, "rqstCnt" : 0, "rcvdCnt" : 0},
            "position"  : { "period" : 0.51,   "last" : None, "rqstCnt" : 0, "rcvdCnt" : 0},
            "config"     : { "period" : 86400, "last" : None, "rqstCnt" : 0, "rcvdCnt" : 0},
            "message"   : { "period" : 0.65,   "last" : None, "rqstCnt" : 0, "rcvdCnt" : 0}
            }

        self.db.query( "select px.lockCryo()")
        self.cryoLocked = True

    def close( self):
        if self.t1 != None:
            self.t1.close()
            self.t1 = None
        if self.t2 != None:
            self.t2.close()
            self.t2 = None
        if self.db != None:
            self.db.close()
            self.db = None

    def run( self):
        runFlag = True
        print "starting run"
        self.pushCmd( "vdi90off")
        lastDbTime = datetime.datetime.now()
        while( runFlag):
            for ( fd, event) in self.p.poll( 100):
                runFlag = runFlag and self.fan[fd](event)
                if not runFlag:
                    break
            n = datetime.datetime.now()
            #print "now: ",n
            if runFlag and not self.waiting:
                #
                # queue up new requests if it is time to
                for k in self.srqst.keys():
                    r = self.srqst[k]
                    if r["last"] == None or (n - r["last"] > datetime.timedelta(0,r["period"])):
                        runFlag &= self.maybePushStatus( k)
                        r["last"] = datetime.datetime.now()
                        r["rqstCnt"] += 1

            if runFlag and (self.dbFlag or (n - lastDbTime > datetime.timedelta(0, 1))):
                    lastDbTime = n
                    runFlag &= self.dbService( select.POLLIN)

            if runFlag and self.needAirRights and not self.haveAirRights:
                qs = "select px.requestRobotAirRights() as rslt"
                qr = self.db.query( qs)
                rslt = qr.dictresult()[0]["rslt"]
                if rslt == "t":
                    self.haveAirRights = True
                    self.pushCmd( "vdi90on", datetime.datetime.now())
                    print "received haveAirRights and setting vdi90on"

            if runFlag and not self.needAirRights and self.haveAirRights:
                self.db.query( "select px.dropRobotAirRights()")    # drop rights and send notify that sample is ready (if it is)
                self.pushCmd( "vdi90off")
                self.haveAirRights = False
                print "dropped Air Rights and setting vdi90off"

        self.close()

    def statusStateParse( self, s):
        self.srqst["state"]["rcvdCnt"] = self.srqst["state"]["rcvdCnt"] + 1

        # One line command to an argument list
        a = s[s.find("(")+1 : s.find(")")].split(',')

        #
        # state ask for the sample changer status -
        #                                          0 = power (1 or 0)
        #                                          1 = auto mode status (1 or 0)
        #                                          2 = default status (1 or 0)
        #                                          3 = tool number or name
        #                                          4 = path name
        #                                          5 = lid number of sample mounted on tool
        #                                          6 = number of the sample on tool
        #                                          7 = lid number of sample mounted on diffractometer
        #                                          8 = number of sample mounted on diffractometer
        #                                          9 = number of plate in tool
        #                                          10 = well number
        #                                          11 = barcode number
        #                                          12 = path running (1 or 0)
        #                                          13 = LN2 regulation running Dewar#1(1 or 0)
        #                                          14 = LN2 regulation running Dewar #2(1 or 0)
        #                                          15 = robot speed ratio (%)
        #                                          16 = puck detection result on Dewar#1
        #                                          17 = puck detection result on Dewar#2
        #                                          18 = position number in Dewar#1
        #                                          19 = position number in Dewar#2


        if len(a) != 20:
            print s
            raise CatsOkError( 'Wrong number of arguments received in status state response: got %d, exptected 20' % (len(a)))
        #                            0            1            2             3           4          5   6   7   8   9  10   11         12           13           14

        if self.statusStateLast == None or self.statusStateLast != s:
            b = []
            i = 0
            #          power       auto stat    default    tool    path     lid#    sam#   mlid#    msam#    plt#   well#   barcode   running     reg1 (1)    reg2 (2)     speed    detc1     detc2  pos#1     pos#2
            #             0           1           2         3       4         5      6       7       8        9     10        11        12          13         14           15        16       17      18       19
            aType = ["::boolean","::boolean","::boolean","::text","::text","::int","::int","::int","::int","::int","::int","::text","::boolean","::boolean","::boolean","::float", "::int", "::int", "::int", "::int"]
            qs = "select cats.setstate( "

            needComma = False
            for zz in a:
                if zz == None or len(zz) == 0:
                    b.append("NULL")
                else:
                    b.append( "'%s'%s" % (zz, aType[i]))

                if needComma:
                    qs = qs+","
                qs = qs + b[i]
                i = i+1
                needComma = True

            qs = qs + ")"
            self.db.query( qs)
            self.statusStateLast = s


        if self.sampleMounted["lid"] != a[7] or self.sampleMounted["sample"] != a[8]:
            self.sampleMounted["lid"] = a[7]
            self.sampleMounted["sample"] = a[8]
            self.sampleMounted["timestamp"] = datetime.datetime.now()
            self.checkMountedSample = True


        if self.sampleTooled["lid"] != a[7] or self.sampleTooled["sample"] != a[8]:
            self.sampleTooled["lid"] = a[7]
            self.sampleTooled["sample"] = a[8]
            self.sampleTooled["timestamp"] = datetime.datetime.now()



        self.robotOn = a[0]      == "1"
        self.robotInRemote= a[1] == "1"
        self.robotError = a[2]   == "1"

        # things to do when in remote mode
        if self.robotInRemote:
            if self.robotError or not self.diES:
                self.pushCmd( "reset")
            elif not self.robotOn:
                self.pushCmd( "on")


        pathName = a[4]
        self.workingPath = pathName

        # mark the end of a path
        if len(self.lastPathName)>0 and self.lastPathName != pathName:
            self.db.query( "select cats.cmdTimingDone()")

        # Nab air rights when we embark on a path requiring them
        if self.lastPathName != pathName and not self.haveAirRights:
            try:
                ndx = self.pathsNeedingAirRights.index(pathName)
            except ValueError:
                self.needAirRights = False
                if pathName != "":
                    print "Current path '%s' does not need air rights" % (pathName)
                else:
                    print "No path running"
            else:
                print "Need Air Rights for path '%s'" % (pathName)
                self.needAirRights = True

        self.lastPathName = pathName

        #
        # Give up air rights when not moving and not in the exclusion zone
        #
        if self.workingPath == "" and not self.inExclusionZone and self.haveAirRights:
            self.needAirRights = False

        #
        # Check if the magnet state makes sense
        #
        if self.checkMountedSample and pathName != 'get' and (datetime.datetime.now() - self.sampleMounted["timestamp"] > datetime.timedelta(0,5)):
            self.checkMountedSample = False
            qr = self.db.query( "select px.getmagnetstate() as ms")
            ms = qr.dictresult()[0]["ms"]
            print "Sample Mounted: ", ms
            print self.sampleMounted
            #
            # check if the robot and the MD2 agree
            #
            if ms == "t" and (self.sampleMounted["lid"] == "" or self.sampleMounted["sample"] == ""):
                print "Sample on diffractometer but robot thinks there isn't: aborting"
                self.pushCmd( "panic")
                if not self.inRecoveryMode:
                    self.inRecoveryMode = True
                    # self.db.query( "select cats.recover_dismount_failure()")
                else:
                    self.needAirRights = False
                    self.inRecoveryMode = False

    def statusDoParse( self, s):
        self.srqst["do"]["rcvdCnt"] = self.srqst["do"]["rcvdCnt"] + 1
        #print "do:", s
        do = s[s.find("(")+1:s.find(")")]
        if do[0] != "1" and do[0] != "0":
            print "Bad 'do' returned: %s" % (do)
            return
        else:
            qs = "select cats.setdo( b'%s'::bit(55))" % (do)
            self.db.query( qs)

        # Calculate Pr2 (robot air rights request)
        lastPr2 = self.Pr2
        self.Pr2 = do[5] == "1"

        # robot needs airrights on rising edge of Pr2
        if not lastPr2 and self.Pr2:
            print "Robot needs air rights now"
            if self.cryoLocked:
                print "Unlocking Cryo..."
                self.db.query( "select px.unlockCryo()")
                self.cryoLocked = False
            self.db.query( "select cats.cmdTimingNeedAir()")

        # robot no longer needs airrights on falling edge of Pr2
        if lastPr2 and not self.Pr2:
            print "Robot no longer needs air rights"
            self.needAirRights = False
            self.db.query( "select cats.cmdTimingNoAir()")
            if not self.cryoLocked:
                print "Locking Cryo..."
                self.db.query( "select px.lockCryo()")
                self.cryoLocked = True


    def statusDiParse( self, s):
        self.srqst["di"]["rcvdCnt"] = self.srqst["di"]["rcvdCnt"] + 1
        di = s[s.find("(")+1:s.find(")")]
        # 111100010000000000000000011000000001110000000000000000000000000000000000000000000101101110000000000
        qs = "select cats.setdi( b'%s')" % (di)
        self.db.query( qs)

        self.diES  = di[1] == "1"

    def statusPositionParse( self, s):
        self.srqst["position"]["rcvdCnt"] = self.srqst["position"]["rcvdCnt"] + 1
        if self.statusPositionLast != None and self.statusPositionLast == s:
            #self.db.query( "select cats.setposition()")
            return

        # One line command to an argument list
        a = s[s.find("(")+1 : s.find(")")].split(',')

        if len(a) != 6:
            raise CatsOkError( 'Wrong number of arguments received in status state response: got %d, exptected 14' % (len(a)))
        #                               0   1   2   3   4  5
        qs = "select cats.setposition( %s, %s, %s, %s, %s, %s)" %  ( a[0], a[1], a[2], a[3], a[4], a[5])
        self.db.query( qs)
        self.statusPositionLast = s
        # print a[0],a[1],a[2],a[3],a[4],a[5]

        #
        # See if we are in the 300mm exclusion zone
        #
        x = float(a[0])
        y = float(a[1])
        z = float(a[2])
        if ((x-self.dpX)*(x-self.dpX)+(y-self.dpY)*(y-self.dpY)+(z-self.dpZ)*(z-self.dpZ)) < 9E4:
            #
            # In exclusion zone
            #
            if not self.inExclusionZone:
                print "In Exclusion zone"
                # we are in the exclusion zone but thought that we were not
                #
                if not self.haveAirRights:
                    # Opps, we don't have air rights.  This is bad.
                    #
                    print "Aborting: need air rights but don't have them"
                    self.pushCmd("panic")
                    self.db.query( "select px.pusherror( 39201,'')")   # post error message
                    self.needAirRights = True
                else:
                    # We have the right to be here.  Just make a note
                    self.db.query( "select px.pusherror( 39200,'')")
                # set the flag
                self.inExclusionZone = True

            #
            # Tell the robot we are in the exclusion zone
            #
            if self.catsExclusionZone == None or self.catsExclusionZone != self.inExclusionZone:
                self.pushCmd( "vdi91on")
                self.catsExclusionZone = True
        else:
            #
            # We are NOT in the exclusion zone
            if self.inExclusionZone:
                print "Not in exclusion zone"
                # but we thought we were
                self.db.query( "select px.pusherror( 30200,'')")
                self.inExclusionZone = False

            if self.haveAirRights:
                # We have air rights, but do we need them anymore?
                #
                if self.workingPath == "":
                    # we are not on a path, perhaps we've aborted?
                    #
                    self.needAirRights = False
                    
            #
            # Tell the robot we are not in the exclusion zone
            #
            if self.catsExclusionZone == None or self.catsExclusionZone != self.inExclusionZone:
                self.pushCmd( "vdi91off")
                self.catsExclusionZone = False

    def statusConfigParse( self, s):
        pass
    
    def statusMessageParse( self, s):
        self.srqst["message"]["rcvdCnt"] = self.srqst["message"]["rcvdCnt"] + 1
        if self.statusMessageLast != None and self.statusMessageLast == s:
            #self.db.query( "select cats.setmessage()")
            #self.db.query( "execute message_noArgs")
            return

        qs = "select cats.setmessage( '%s')" % (s)
        self.db.query( qs)
        self.statusMessageLast = s

        

#
# Default usage
#
if __name__ == '__main__':
    iFlag = True
    rFlag = True

    while rFlag:
        while iFlag:
            print "Starting Up..."
            try:
                z = CatsOk()
            except CatsOkError, e:
                time.sleep( 10)
            else:
                iFlag = False
        try:
            z.run()
        except CatsOkError:
            z.close()
        time.sleep( 10)
        iFlag = True

