begin;
DROP SCHEMA cats cascade;
CREATE SCHEMA cats;
GRANT USAGE ON SCHEMA cats TO PUBLIC;

--
-- Status
--
CREATE TABLE cats.states (
       csKey serial primary key,
       csTSStart timestamp with time zone default now(),
       csTSLast  timestamp with time zone default now(),
       csStn bigint references px.stations (stnkey),

       csPower boolean,
       csAutoMode boolean,
       csDefaultStatus boolean,
       csToolNumber text,
       csPathName text,
       csLidNumberOnTool integer,
       csSampleNumberOnTool integer,
       csLidNumberMounted integer,
       csSampleNumberMounted integer,
       csPlateNumber integer,
       csWellNumber integer,
       csBarcode text,
       csPathRunning boolean,
       csLN2Reg1 boolean,
       csLN2Reg2 boolean,
       csToolSpeed float,
       csPuckDetect1 integer,
       csPuckDetect2 integer,
       csPosNum1 integer,
       csPosNum2 integer,
);
ALTER TABLE cats.states OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.statesInsertTF() returns trigger as $$
  DECLARE
    t RECORD;
  BEGIN
    SELECT * INTO t FROM cats.states WHERE csStn=px.getStation() ORDER BY csTSLast DESC LIMIT 1;
    IF FOUND THEN
      IF
        t.csPower = NEW.csPower AND
        t.csAutoMode = NEW.csAutoMode AND
        t.csDefaultStatus = NEW.csDefaultStatus AND
        t.csToolNumber = NEW.csToolNumber AND
        t.csPathName = NEW.csPathName AND
        t.csLidNumberOnTool = NEW.csLidNumberOnTool AND
        t.csSampleNumberOnTool = NEW.csSampleNumberOnTool AND
        t.csLidNumberMounted = NEW.csLidNumberMounted AND
        t.csSampleNumberMounted = NEW.csSampleNumberMounted AND
        t.csPlateNumber = NEW.csPlateNumber AND
        t.csWellNumber = NEW.csWellNumber AND
        t.csBarcode = NEW.csBarcode AND
        t.csPathRunning = NEW.csPathRunning AND
        t.csLN2Reg1 = NEW.csLN2Reg1 AND
        t.csLN2Reg2 = NEW.csLN2Reg2 AND
        t.csToolSpeed  = NEW.csToolSpeed AND
	t.csPuckDetect1 = NEW.csPuckDetect1 AND
	t.csPuckDetect2 = NEW.csPuckDetect2 AND
	t.csPosNum1 = NEW.csPosNum1 AND
	t.csPosNum2 = NEW.csPosNum2

      THEN
        UPDATE cats.states SET csTSLast = now() WHERE csKey = t.csKey;
        RETURN NULL;
      END IF;
    END IF;
    IF t.csPathRunning and not NEW.csPathRunning THEN
      --
      -- Clear the next samples queue so we can request a new sample later
      --
      DELETE FROM px.nextsamples WHERE nsstn=px.getStation();
    END IF;
    DELETE FROM cats.states WHERE cskey < NEW.cskey and csstn=px.getStation();
    PERFORM px.kvset( px.getstation(), 'cats.path', NEW.csPathName);
    RETURN NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.statesInsertTF() OWNER TO lsadmin;

CREATE TRIGGER statesInsertTrigger BEFORE INSERT ON cats.states FOR EACH ROW EXECUTE PROCEDURE cats.statesInsertTF();

drop function cats.setstate(boolean,boolean,boolean,text,text,int,int,int,int,int,int,text,boolean,boolean,boolean);

CREATE OR REPLACE FUNCTION cats.setstate (
--                                          state(0,1,2,3,4,5,6,7,’¡Ä,19)
--state ask for the sample changer status -
--                                          0 = power (1 or 0)
--                                          1 = auto mode status (1 or 0)
--                                          2 = default status (1 or 0)
--                                          3 = tool number or name
--                                          4 = path name
--                                          5 = lid number of sample mounted on tool
--                                          6 = number of the sample on tool
--                                          7 = lid number of sample mounted on diffractometer
--                                          8 = number of sample mounted on diffractometer
--                                          9 = number of plate in tool
--                                          10 = well number
--                                          11 = barcode number
--                                          12 = path running (1 or 0)
--                                          13 = LN2 regulation running Dewar#1(1 or 0)
--                                          14 = LN2 regulation running Dewar #2(1 or 0)
--                                          15 = robot speed ratio (%)
--                                          16 = puck detection result on Dewar#1
--                                          17 = puck detection result on Dewar#2
--                                          18 = position number in Dewar#1
--                                          19 = position number in Dewar#2


       power boolean,			--  0
       autoMode boolean,		--  1
       defaultStatus boolean,		--  2
       toolNumber text,			--  3
       pathName text,			--  4
       lidNumberOnTool integer,		--  5
       sampleNumberOnTool integer,	--  6
       lidNumberMounted integer,	--  7
       sampleNumberMounted integer,	--  8
       plateNumber integer,		--  9
       wellNumber integer,		-- 10
       barcode text,			-- 11
       pathRunning boolean,		-- 12
       LN2Reg1 boolean,			-- 13
       LN2Reg2 boolean,			-- 14
       toolSpeed float,			-- 15
       puckDetect1 integer,		-- 16
       puckDetect2 integer,		-- 17
       posNum1 integer,			-- 18
       posNum2 integer			-- 19
) returns int as $$
DECLARE
BEGIN
  INSERT INTO cats.states ( csStn, csPower, csAutoMode, csDefaultStatus, csToolNumber, csPathName,
              csLidNumberOnTool, csSampleNumberOnTool, csLidNumberMounted, csSampleNumberMounted, csPlateNumber,
              csWellNumber, csBarcode, csPathRunning, csLN2Reg1, csLN2Reg2, csToolSpeed, csPuckDetect1, csPuckDetect2, csPosNum1, csPosNum2)
       VALUES (  px.getStation(), power, autoMode, defaultStatus, toolNumber,  pathName,
                 lidNumberOnTool, sampleNumberOnTool, lidNumberMounted, sampleNumberMounted, plateNumber,
                 wellNumber, barcode, pathRunning, LN2Reg1, LN2Reg2, toolSpeed, puckDetect1, puckDetect2, posNum1, posNum2);


  IF FOUND then
      PERFORM px.setMountedSample( toolNumber::text, lidNumberMounted::int, sampleNumberMounted::int);
      PERFORM px.setTooledSample( toolNumber::text, lidNumberOnTool::int, sampleNumberOnTool::int);
    return 1;
  ELSE
    return 0;
  END IF;
  return 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

ALTER FUNCTION cats.setstate (
       power boolean,			--  0
       autoMode boolean,		--  1
       defaultStatus boolean,		--  2
       toolNumber text,			--  3
       pathName text,			--  4
       lidNumberOnTool integer,		--  5
       sampleNumberOnTool integer,	--  6
       lidNumberMounted integer,	--  7
       sampleNumberMounted integer,	--  8
       plateNumber integer,		--  9
       wellNumber integer,		-- 10
       barcode text,			-- 11
       pathRunning boolean,		-- 12
       LN2Reg1 boolean,			-- 13
       LN2Reg2 boolean,			-- 14
       toolSpeed float,			-- 15
       puckDetect1 integer,		-- 16
       puckDetect2 integer,		-- 17
       posNum1 integer,			-- 18
       posNum2 integer			-- 19
) OWNER TO lsadmin;



CREATE OR REPLACE FUNCTION cats.setState() returns void as $$
  DECLARE
    k bigint;
  BEGIN
    SELECT csKey INTO k FROM cats.states WHERE csStn = px.getStation() ORDER BY csTSLast DESC LIMIT 1;
    IF FOUND THEN
      UPDATE cats.states SET csTSLast = now() WHERE csKey = k;
    END IF;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setState() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.setStateInsertTF() returns trigger as $$
  DECLARE
    oldState record;
  BEGIN
    SELECT * INTO oldState FROM cats.states WHERE csstn=px.getStation() and cskey != NEW.cskey ORDER BY cskey DESC LIMIT 1;
    IF FOUND and (coalesce(NEW.csLidNumberMounted,0) != coalesce(oldstate.csLidNumberMounted,0) or coalesce(NEW.csSampleNumberMounted,0) != coalesce(oldstate.csSampleNumberMounted,0)) THEN
      PERFORM px.endTransfer( NEW.csstn);
    END IF;
    RETURN NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setStateInsertTF() OWNER TO lsadmin;

CREATE TRIGGER setStateInsertTigger BEFORE INSERT ON cats.states FOR EACH ROW EXECUTE PROCEDURE cats.setStateInsertTF();


CREATE OR REPLACE FUNCTION px.setMountedSample( tool text, lid int, sampleno int) RETURNS int AS $$
  DECLARE
    cstn int;
    cdwr int;
    ccyl int;
    csmp int;
    sampId int;
    toolId int;
    diffId int;
    ntfy text;
    
  BEGIN
    cstn := px.getStation();
    toolId = (cstn<<24) | (1<<16);
    diffId = (cstn<<24) | (2<<16);
    sampId = 0;

    IF lid::int > 0 and sampleno::int > 0 THEN
    -- compute our position ID from the lid and sample number returned
    -- For sample mounted
      cdwr := lid + 2;
      SELECT ((sampleno-1)/ctnsamps)::int + ctoff, (sampleno-1)%ctnsamps+1 INTO ccyl,csmp FROM cats._cylinder2tool WHERE ctToolName=tool or ctToolNo::text=tool LIMIT 1;
      sampId = (cstn<<24) | (cdwr<<16) | (ccyl<<8) | (csmp);
      
      UPDATE px.holderPositions set hpTempLoc = 0 WHERE hpTempLoc = diffId;
      UPDATE px.holderPositions set hpTempLoc = diffId WHERE hpId = sampId;
    ELSE
      UPDATE px.holderPositions set hpTempLoc = 0 WHERE hpTempLoc = diffId;
    END IF;

    SELECT INTO ntfy cnotifysample FROM px._config WHERE cstnkey=cstn;
    EXECUTE 'NOTIFY '||ntfy;
    return sampId;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION px.setMountedSample( text, int, int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION px.setTooledSample( tool text, lid int, sampleno int) RETURNS int AS $$
  DECLARE
    cstn int;
    cdwr int;
    ccyl int;
    csmp int;
    sampId int;
    toolId int;
    diffId int;
    
  BEGIN
    cstn := px.getStation();
    toolId = (cstn<<24) | (1<<16);
    diffId = (cstn<<24) | (2<<16);
    sampId = 0;

    IF lid::int > 0 and sampleno::int > 0 THEN
    -- computer our position ID from the lid and sample number returned
    -- For sample mounted
      cdwr := lid + 2;
      SELECT ((sampleno-1)/ctnsamps)::int + ctoff, (sampleno-1)%ctnsamps+1 INTO ccyl,csmp FROM cats._cylinder2tool WHERE ctToolName=tool or ctToolNo::text=tool LIMIT 1;
      sampId = (cstn<<24) | (cdwr<<16) | (ccyl<<8) | (csmp);
      
      UPDATE px.holderPositions set hpTempLoc = 0 WHERE hpTempLoc = toolId;
      UPDATE px.holderPositions set hpTempLoc = toolId WHERE hpId = sampId;
    ELSE
      UPDATE px.holderPositions set hpTempLoc = 0 WHERE hpTempLoc = toolId;
    END IF;
    return sampId;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION px.setTooledSample( text, int, int) OWNER TO lsadmin;

CREATE TABLE cats.do (
       doKey serial primary key,
       doTSStart    timestamp with time zone default now(),
       doTSLast     timestamp with time zone default now(),
       doStn bigint references px.stations (stnKey),
       doo bit(55)
);
ALTER TABLE cats.do OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.doInsertTF() returns trigger AS $$
  DECLARE
    prev record;
  BEGIN
    SELECT * INTO prev FROM cats.do WHERE dostn=px.getStation() ORDER BY doKey DESC LIMIT 1;
    IF FOUND AND prev.doo=NEW.doo THEN
      UPDATE cats.do SET doTSLast=now() WHERE doKey=prev.doKey;
      RETURN NULL;
    END IF;
    DELETE FROM cats.do WHERE dokey < NEW.dokey and dostn=px.getStation();
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.doInsertTF() OWNER TO lsadmin;
CREATE TRIGGER doInsertTrigger BEFORE INSERT ON cats.do FOR EACH ROW EXECUTE PROCEDURE cats.doInsertTF();

CREATE OR REPLACE FUNCTION cats.setdo( theDo bit(99)) RETURNS VOID AS $$
  INSERT INTO cats.do (doStn, doo) VALUES (px.getStation(), $1);
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.setdo( bit(99)) OWNER TO lsadmin;

CREATE TABLE cats.di (
       diKey serial primary key,
       diTSStart    timestamp with time zone default now(),
       diTSLast     timestamp with time zone default now(),
       diStn bigint references px.stations (stnKey),
       dii bit(99)
);
ALTER TABLE cats.di OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.diInsertTF() returns trigger AS $$
  DECLARE
    prev record;
    msgs record;
  BEGIN
    SELECT * INTO prev FROM cats.di WHERE distn=px.getStation() ORDER BY diKey DESC LIMIT 1;
    --
    
    IF FOUND THEN
      --
      -- is there a non trivial change?
      --
      IF  ~(b'1'::bit(99)>>31) & prev.dii = ~(b'1'::bit(99)>>31) &  NEW.dii THEN
        --
        -- No: just update the time stamp
        --
        UPDATE cats.di SET diTSLast=now() WHERE diKey=prev.diKey;
        RETURN NULL;
      END IF;

      --
      -- A non trivial change was found.  Perhaps send out some messages
      --
      FOR msgs IN SELECT * FROM cats.di2error WHERE (prev.dii # NEW.dii) & d2ei != b'0'::bit(99) LOOP
        IF (msgs.d2ei & NEW.dii) != b'0'::bit(99) THEN
        --
        -- The new value is high
        --
          PERFORM px.pushError( msgs.d2eeup, '');
        ELSE
        --
        -- and low here
        --
          PERFORM px.pushError( msgs.d2eedown, '');
        END IF;
      END LOOP;
    END IF;
    DELETE FROM cats.di WHERE dikey<NEW.dikey and distn=px.getStation();
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.diInsertTF() OWNER TO lsadmin;
CREATE TRIGGER diInsertTrigger BEFORE INSERT ON cats.di FOR EACH ROW EXECUTE PROCEDURE cats.diInsertTF();

CREATE OR REPLACE FUNCTION cats.chkdi( odi bit(99), ndi bit(99), bt int) returns boolean AS $$
--
-- Compares an old di entry (odi) with a new di entry (ndi) and looks at a bit (bt)
-- returns
--   NULL if no change
--   FALSE if change was from 1 to 0
--   TRUE  if change was from 0 to 1
--
  DECLARE
    o boolean;
    n boolean;
  BEGIN
    o := ((B'1'::bit(99) >> bt)  & odi) != b'0'::bit(99);
    n := ((B'1'::bit(99) >> bt)  & ndi) != b'0'::bit(99);
    IF o = n THEN
      return NULL;
    ELSEIF n THEN
      return TRUE;
    END IF;
    return FALSE;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.chkdi( bit(99), bit(99), int) OWNER TO lsadmin;



CREATE TYPE cats.getrobotstatetype AS ( power boolean, lid1 boolean, lid2 boolean, lid3 boolean, regon boolean, magon boolean, toolopen boolean, path text, progress float);
CREATE OR REPLACE FUNCTION cats.getrobotstate() returns cats.getrobotstatetype AS $$
  DECLARE
    rtn cats.getrobotstatetype;
    sti bit(99);
    sto bit(55);
  BEGIN
    SELECT dii INTO sti FROM cats.di WHERE distn = px.getstation() ORDER BY dikey desc LIMIT 1;
    IF FOUND THEN
      rtn.lid1     := (b'1'::bit(99) >> 21) & sti != 0::bit(99);
      rtn.lid2     := (b'1'::bit(99) >> 22) & sti != 0::bit(99);
      rtn.lid3     := (b'1'::bit(99) >> 23) & sti != 0::bit(99);
      rtn.toolopen := (b'1'::bit(99) >> 24) & sti != 0::bit(99);
    END IF;
    SELECT doo INTO sto FROM cats.do WHERE dostn = px.getstation() ORDER BY dokey desc LIMIT 1;
    IF FOUND THEN
      rtn.magon := (b'1'::bit(55) >> 4) & sto != 0::bit(55);
    END IF;
    SELECT cspower, csln2reg1, cspathname INTO rtn.power, rtn.regon, rtn.path FROM cats.states WHERE csstn=px.getstation() ORDER BY cskey desc limit 1;
    SELECT cats.fractiondone() INTO rtn.progress;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getrobotstate() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.getrobotstate( theStn bigint) returns cats.getrobotstatetype AS $$
  DECLARE
    rtn cats.getrobotstatetype;
    sti bit(99);
    sto bit(55);
  BEGIN
    SELECT dii INTO sti FROM cats.di WHERE distn = theStn ORDER BY dikey desc LIMIT 1;
    IF FOUND THEN
      rtn.lid1     := (b'1'::bit(99) >> 21) & sti != 0::bit(99);
      rtn.lid2     := (b'1'::bit(99) >> 22) & sti != 0::bit(99);
      rtn.lid3     := (b'1'::bit(99) >> 23) & sti != 0::bit(99);
      rtn.toolopen := (b'1'::bit(99) >> 24) & sti != 0::bit(99);
    END IF;
    SELECT doo INTO sto FROM cats.do WHERE dostn = theStn ORDER BY dokey desc LIMIT 1;
    IF FOUND THEN
      rtn.magon := (b'1'::bit(55) >> 4) & sto != 0::bit(55);
    END IF;
    SELECT cspower, csln2reg1, cspathname INTO rtn.power, rtn.regon, rtn.path FROM cats.states WHERE csstn=theStn ORDER BY cskey desc limit 1;
    SELECT cats.fractiondone( theStn) INTO rtn.progress;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getrobotstate( bigint) OWNER TO lsadmin;


--CREATE TYPE cats.getrobotstatetype AS ( power boolean, lid1 boolean, lid2 boolean, lid3 boolean, regon boolean, magon boolean, toolopen boolean, path text, progress float);
CREATE OR REPLACE FUNCTION cats.getrobotstatexml( thePid text, theStn bigint) returns xml AS $$
  DECLARE
    rtn xml;
  BEGIN
    PERFORM 1 WHERE rmt.checkstnaccess( theStn, thePid);
    IF FOUND THEN
      SELECT cats.getrobotstatexml( theStn) INTO rtn;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getrobotstatexml( text, bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.getrobotstatexml( theStn int) returns xml AS $$
  DECLARE
    rtn xml;
    tmp cats.getrobotstatetype;
    msg text;
    sid int;
    puckState int;
    ms  boolean;
  BEGIN

    SELECT ((((b'111111111'::bit(99)>>12) & dii)<<12) & b'111111111'::bit(99))::bit(9)::int INTO puckState FROM cats.di WHERE distn=theStn;

    SELECT px.kvget( theStn::int, 'SamplePresent') = 'True' INTO ms;

    SELECT etverbose INTO msg FROM px.nexterrors( theStn) WHERE etid>=30000 and etid<40000 ORDER BY etkey DESC LIMIT 1;
    IF NOT FOUND THEN
      msg := '';
    END IF;

    SELECT px.getcurrentsampleid(theStn::int) into sid;
    IF NOT FOUND THEN
      sid := 0;
    END IF;

    SELECT * INTO tmp FROM cats.getrobotstate( theStn);
    rtn := xmlelement( name "statusReport",
                       xmlelement(name "robotStatus",
                                   xmlattributes( 'true' as success, theStn as stn, tmp.power as power, tmp.lid1 as lid1, tmp.lid2 as lid2, tmp.lid3 as lid3,
                                                   tmp.regon as regon, tmp.magon as magon, tmp.toolopen as toolopen, tmp.path as path, tmp.progress::text as progress,
                                                   msg as status, sid as currentsample, ms as mounted, puckState::text as pucks)));

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getrobotstatexml( int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.getrobotstatekvpxml( theStn int) returns xml AS $$
  DECLARE
    rtn xml;
    tmp cats.getrobotstatetype;
    msg text;
    sid int;
    puckState int;
    ms  boolean;
  BEGIN

    SELECT ((((b'111111111'::bit(99)>>12) & dii)<<12) & b'111111111'::bit(99))::bit(9)::int INTO puckState FROM cats.di WHERE distn=theStn;

    SELECT px.kvget( theStn, 'SamplePresent') = 'True' INTO ms;

    SELECT etverbose INTO msg FROM px.nexterrors( theStn) WHERE etid>=30000 and etid<40000 ORDER BY etkey DESC LIMIT 1;
    IF NOT FOUND THEN
      msg := '';
    END IF;

    SELECT px.getcurrentsampleid(theStn::int) into sid;
    IF NOT FOUND THEN
      sid := 0;
    END IF;

    SELECT * INTO tmp FROM cats.getrobotstate( theStn);
    
    rtn := xmlelement( name "robotStatus", xmlelement( name kvpair, xmlattributes( 'success'  as name, 'true'    as value)),
                                           xmlelement( name kvpair, xmlattributes( 'stn'      as name, theStn    as value)),
                                           xmlelement( name kvpair, xmlattributes( 'lid1'     as name, tmp.lid1  as value)),
                                           xmlelement( name kvpair, xmlattributes( 'lid2'     as name, tmp.lid2  as value)),
                                           xmlelement( name kvpair, xmlattributes( 'lid3'     as name, tmp.lid3  as value)),
                                           xmlelement( name kvpair, xmlattributes( 'regon'    as name, tmp.regon as value)),
                                           xmlelement( name kvpair, xmlattributes( 'magon'    as name, tmp.magon as value)),
                                           xmlelement( name kvpair, xmlattributes( 'toolopen' as name, tmp.toolopen as value)),
                                           xmlelement( name kvpair, xmlattributes( 'path'     as name, coalesce(tmp.path,'')  as value)),
                                           xmlelement( name kvpair, xmlattributes( 'progress' as name, tmp.progress::text as value)),
                                           xmlelement( name kvpair, xmlattributes( 'status'   as name, msg       as value)),
                                           xmlelement( name kvpair, xmlattributes( 'currentsample' as name, sid  as value)),
                                           xmlelement( name kvpair, xmlattributes( 'mounted'  as name, ms        as value)),
                                           xmlelement( name kvpair, xmlattributes( 'pucks'    as name, puckState::text as value)));


                      
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getrobotstatekvpxml( bigint) OWNER TO lsadmin;


CREATE TABLE cats.o2error (
--
-- Maps a changing bit in Di with an error message in px.errors
--
       o2ekey serial primary key,	-- our key
       o2eo bit(99) unique,			-- a mask with one bit set
       o2eeup int references px.errors (eid) default null,	-- message when bit goes high
       o2eedown int references px.errors (eid) default null	-- message when bit goes low
);
ALTER TABLE cats.o2error OWNER TO lsadmin;



CREATE TABLE cats.di2error (
--
-- Maps a changing bit in Di with an error message in px.errors
--
       d2ekey serial primary key,	-- our key
       d2ei bit(99) unique,			-- a mask with one bit set
       d2eeup int references px.errors (eid) default null,	-- message when bit goes high
       d2eedown int references px.errors (eid) default null	-- message when bit goes low
);
ALTER TABLE cats.di2error OWNER TO lsadmin;


INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 29100, 'Cryogenic Sensor Failure', 'A cryogenic sensor has failed: the Dewar may starting warming or LN2 may start overflowing in the hutch');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30100, 'Cryogenic Sensors OK',     'The cryogenic sensors are now OK');

INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 0, 30100, 29100);

INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 29101, 'Emergency Stop Pressed or Air Pressure Loss', 'At least on of the emergency stop buttons has been pressed or air pressure has been lost.  Trun an estop button CCW to release');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30101, 'Emergency Stop Buttons and Air Pressure OK', 'Emergency stop and air pressures systems OK');

INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 29102, 'Collision Detected', 'The robot arm has detected a collision.  This is not good.  If the arm is in the Dewar then call the LS-CAT staff even if it is late at night or early in the morning');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30102, 'Collision Cleared',  'The collision has been cleared.  Time to recover.');

INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('warning', 29103, 'LN2 High Level Alarm',     'The dewar is now over full.  Contact LS-CAT staff.  Watch for Low O2 warning in hutch.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30103, 'LN2 High Level Alarm Off', 'The LN2 level is now below the overfill mark');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39104, 'LN2 Level High',       'The dewar is now full.  Hopefully the LN2 refill will stop');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30104, 'LN2 High Level OK',    'The LN2 level is now below the high mark');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39105, 'LN2 Level Low',         'The dewar LN2 level is now low.  Hopefully the LN2 refill will start');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30105, 'LN2 Low Level OK',      'The LN2 level is now above the low mark');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('warning', 29106, 'LN2 Low Level Alarm',  'The dewar LN2 level is too low.  Remove your pucks and call the LS-CAT staff');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30106, 'LN2 Low Level OK',    ' The LN2 level is now above the low mark');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39107, 'Gas in fill line',       'Gas is detected in the fill line.  This is usually not a bad thing');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30107, 'Liquid in fill line',    'Liquid has been detected in the fill line.  This is good if the Dewar is being filled');

INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 1, 30101, 29101);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 2, 30102, 29102);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 3, 30103, 29103);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 4, 30104, 39104);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 5, 30105, 39105);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 6, 30106, 29106);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 7, 30107, 39107);


INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39112, 'Puck 1 in Lid 1 Removed',   'Puck 1 in Lid 1 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30112, 'Puck 1 in Lid 1 in Place',  'Puck 1 in Lid 1 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39113, 'Puck 2 in Lid 1 Removed',   'Puck 2 in Lid 1 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30113, 'Puck 2 in Lid 1 in Place',  'Puck 2 in Lid 1 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39114, 'Puck 3 in Lid 1 Removed',   'Puck 3 in Lid 1 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30114, 'Puck 3 in Lid 1 in Place',  'Puck 3 in Lid 1 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39115, 'Puck 1 in Lid 2 Removed',   'Puck 1 in Lid 2 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30115, 'Puck 1 in Lid 2 in Place',  'Puck 1 in Lid 2 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39116, 'Puck 2 in Lid 2 Removed',   'Puck 2 in Lid 2 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30116, 'Puck 2 in Lid 2 in Place',  'Puck 2 in Lid 2 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39117, 'Puck 3 in Lid 2 Removed',   'Puck 3 in Lid 2 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30117, 'Puck 3 in Lid 2 in Place',  'Puck 3 in Lid 2 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39118, 'Puck 1 in Lid 3 Removed',   'Puck 1 in Lid 3 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30118, 'Puck 1 in Lid 3 in Place',  'Puck 1 in Lid 3 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39119, 'Puck 2 in Lid 3 Removed',   'Puck 2 in Lid 3 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30119, 'Puck 2 in Lid 3 in Place',  'Puck 2 in Lid 3 has been detected: the robot will be able to move to this position again.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39120, 'Puck 3 in Lid 3 Removed',   'Puck 3 in Lid 3 is no longer detected: the robot will not move to this position anymore.');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30120, 'Puck 3 in Lid 3 in Place',  'Puck 3 in Lid 3 has been detected: the robot will be able to move to this position again.');

INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 12, 30112, 39112);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 13, 30113, 39113);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 14, 30114, 39114);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 15, 30115, 39115);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 16, 30116, 39116);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 17, 30117, 39117);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 18, 30118, 39118);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 19, 30119, 39119);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 20, 30120, 39120);


INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39121, 'Lid 1 Not Open',   'Lid 1 is not completely open (and is probably completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30121, 'Lid 1 Open',       'Lid 1 is completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39122, 'Lid 2 Not Open',   'Lid 2 is not completely open (and is probably completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30122, 'Lid 2 Open',       'Lid 2 is completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39123, 'Lid 3 Not Open',   'Lid 3 is not completely open (and is probably completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30123, 'Lid 3 Open',       'Lid 3 is completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39124, 'Tool Not Open',   'The tool is not completely open (and may be closed)');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30124, 'Tool Open',       'The tool is completely open');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39125, 'Tool Not Closed',   'The tool is not completely closed (and may be open)');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30125, 'Tool Close',       'The tool is completely closed');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39126, 'Limit Switch 1 Closed',   'The gripper is in the diffractometer position');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30126, 'Limit Switch 1 Open',     'The gripper is not in the diffractometer position');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39127, 'Limit Switch 2 Closed',   'The gripper is in the dewar position');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30127, 'Limit Switch 2 Open',     'The gripper is not in the dewar position');

INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 21, 30121, 39121);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 22, 30122, 39122);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 23, 30123, 39123);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 24, 30124, 39124);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 25, 30125, 39125);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 26, 30126, 39126);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 27, 30127, 39127);


INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39147, 'Process Input 5 is 1',  'Process Input 5 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30147, 'Process Input 5 is 0',  'Process Input 5 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39148, 'Process Input 6 is 1',  'Process Input 6 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30148, 'Process Input 6 is 0',  'Process Input 6 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39149, 'Process Input 7 is 1',  'Process Input 7 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30149, 'Process Input 7 is 0',  'Process Input 7 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39150, 'Process Input 8 is 1',  'Process Input 8 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30150, 'Process Input 8 is 0',  'Process Input 8 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39151, 'Process Input 9 is 1',  'Process Input 9 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30151, 'Process Input 9 is 0',  'Process Input 9 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39152, 'Process Input 10 is 1',  'Process Input 10 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30152, 'Process Input 10 is 0',  'Process Input 10 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39153, 'Process Input 11 is 1',  'Process Input 11 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30153, 'Process Input 11 is 0',  'Process Input 11 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39154, 'Process Input 12 is 1',  'Process Input 12 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30154, 'Process Input 12 is 0',  'Process Input 12 is 0, whatever that means');

INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 47, 30147, 39147);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 48, 30148, 39148);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 49, 30149, 39149);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 50, 30150, 39150);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 51, 30151, 39151);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 52, 30152, 39152);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 53, 30153, 39153);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 54, 30154, 39154);


INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39189, 'Vi0 is 1',  'Virtual Input 0 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30189, 'Vi0 is 0',  'Virtual Input 0 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39190, 'Vi1 is 1',  'Virtual Input 1 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30190, 'Vi1 is 0',  'Virtual Input 1 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39191, 'Vi2 is 1',  'Virtual Input 2 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30191, 'Vi2 is 0',  'Virtual Input 2 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39192, 'Vi3 is 1',  'Virtual Input 3 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30192, 'Vi3 is 0',  'Virtual Input 3 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39193, 'Vi4 is 1',  'Virtual Input 4 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30193, 'Vi4 is 0',  'Virtual Input 4 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39194, 'Vi5 is 1',  'Virtual Input 5 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30194, 'Vi5 is 0',  'Virtual Input 5 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39195, 'Vi6 is 1',  'Virtual Input 6 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30195, 'Vi6 is 0',  'Virtual Input 6 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39196, 'Vi7 is 1',  'Virtual Input 7 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30196, 'Vi7 is 0',  'Virtual Input 7 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39197, 'Vi8 is 1',  'Virtual Input 8 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30197, 'Vi8 is 0',  'Virtual Input 8 is 0, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 39198, 'Vi9 is 1',  'Virtual Input 9 is 1, whatever that means');
INSERT INTO px.errors (eSeverity, eid, eTerse, eVerbose) VALUES ('message', 30198, 'Vi9 is 0',  'Virtual Input 9 is 0, whatever that means');

INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 89, 30189, 39189);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 90, 30190, 39190);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 91, 30191, 39191);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 92, 30192, 39192);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 93, 30193, 39193);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 94, 30194, 39194);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 95, 30195, 39195);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 96, 30196, 39196);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 97, 30197, 39197);
INSERT INTO cats.di2error (d2ei, d2eeup, d2eedown) VALUES ( b'1'::bit(99) >> 98, 30198, 39198);



CREATE OR REPLACE FUNCTION cats.setdi( theDi bit(99)) RETURNS VOID AS $$
  INSERT INTO cats.di (diStn, dii) VALUES (px.getStation(), $1);
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.setdi( bit(99)) OWNER TO lsadmin;




CREATE TABLE cats.io (
       ioKey serial primary key,
       ioTSStart timestamp with time zone default now(),
       ioTSLast  timestamp with time zone default now(),
       ioStn bigint references px.stations (stnkey),

       ioCryoOK boolean,	-- 00 Cryogen Sensors OK:  1 = OK
       ioESAP   boolean,	-- 01 Emergency Stop and Air Pressure OK: 1 = OK
       ioCollisionOK boolean,	-- 02 Collision Sensor OK: 1 = No Collision
       ioCryoHighAlarm boolean, -- 03 Cryogen High Level Alarm: 1 = No Alarm
       ioCryoHigh boolean,	-- 04 Cryogen High Level: 1 = high level reached
       ioCryoLow  boolean,	-- 05 Cryogen Low Level: 1 = low level reached
       ioCryoLowAlarm boolean,	-- 06 Cryogen Low Level Alarm: 1 = no alarm
       ioCryoLiquid boolean,	-- 07 Cryogen Liquid Detection: 0=Gas, 1=Liquid
       ioInput1 boolean,	-- 08
       ioInput2 boolean,	-- 09
       ioInput3 boolean,	-- 10
       ioInput4 boolean,	-- 11
       ioCassette1 boolean,	-- 12 Cassette 1 presence:  1 = cassette in place
       ioCassette2 boolean,	-- 13 Cassette 2 presence:  1 = cassette in place
       ioCassette3 boolean,	-- 14 Cassette 3 presence:  1 = cassette in place
       ioCassette4 boolean,	-- 15 Cassette 4 presence:  1 = cassette in place
       ioCassette5 boolean,	-- 16 Cassette 5 presence:  1 = cassette in place
       ioCassette6 boolean,	-- 17 Cassette 6 presence:  1 = cassette in place
       ioCassette7 boolean,	-- 18 Cassette 7 presence:  1 = cassette in place
       ioCassette8 boolean,	-- 19 Cassette 8 presence:  1 = cassette in place
       ioCassette9 boolean,	-- 20 Cassette 9 presence:  1 = cassette in place
       ioLid1Open boolean,	-- 21 Lid 1 Opened: 1 = lid completely opened
       ioLid2Open boolean,	-- 22 Lid 2 Opened: 1 = lid completely opened
       ioLid3Open boolean,	-- 23 Lid 3 Opened: 1 = lid completely opened
       ioToolOpened boolean,	-- 24 Tool Opened: 1 = tool completely opened
       ioToolClosed boolean,	-- 25 Tool Closed: 1 = tool completely closed
       ioLimit1 boolean,	-- 26 Limit Switch 1:  0 = gripper in diffractometer position
       ioLimit2 boolean,	-- 27 Limit Switch 2:  0 = gripper in dewar position
       ioTool boolean,		-- 28 Tool Changer:	0 = tool gripped, 1 = tool released
       ioToolOC boolean,	-- 29 Tool Open/Close:  0 = tool closed, 1 = tool opened
       ioFast boolean,		-- 30 Fast Output: 0 = contact open, 1 = contact closed
       ioUnlabed1 boolean,	-- 31 Usage not documented
       ioMagnet boolean,	-- 32 Output Process Information 2 [sic], Magnet ON: 0 = contact open, 1 = contact closed
       ioOutput2 boolean,	-- 33 Output Process Information 2: 0 = contact open, 1 = contact closed
       ioOutput3 boolean,	-- 34 Output Process Information 3: 0 = contact open, 1 = contact closed
       ioOutput4 boolean,	-- 35 Output Process Information 4: 0 = contact open, 1 = contact closed
       ioGreen boolean,		-- 36 Green Light (Power, air, and Modbus network OK): 1 = OK
       ioPILZ boolean,		-- 37 PILZ Relay Reset: 1 = reset of the relay
       ioServoOn boolean,	-- 38 Servo Card ON: 1 = card on
       ioServoRot boolean,	-- 39 Servo Card Rotation +/-: 0 = toard the diffractometer, 1 = toward the dewar
       ioLN2C boolean,		-- 40 Cryogen Valve LN2_C: 0 = closed, 1 = open
       ioLN2E boolean,		-- 41 Cryogen Valve LN2_E: 0 = closed, 1 = open
       ioLG2E boolean,		-- 42 Cryogen Valve GN2_E: 0 = closed, 1 = open
       ioHeater boolean,	-- 43 Heater ON/ODD: 0 = off, 1 = on
       ioUnlabed2 boolean,	-- 44 Usage not documented
       ioUnlabed3 boolean,	-- 45 Usage not documented
       ioUnlabed4 boolean,	-- 46 Usage not documented
       ioUnlabed5 boolean	-- 47 Usage not documented
);
ALTER TABLE cats.io OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.ioInsertTF() returns trigger as $$
  DECLARE
    t record;
  BEGIN
    SELECT * INTO t FROM cats.io WHERE ioStn=px.getStation() ORDER BY ioTSLast DESC LIMIT 1;
    IF FOUND THEN
      IF
        t.ioCryoOK = NEW.ioCryoOK AND
        t.ioESAP = NEW.ioESAP AND
        t.ioCollisionOK = NEW.ioCollisionOK AND
        t.ioCryoHighAlarm = NEW.ioCryoHighAlarm AND
        t.ioCryoHigh = NEW.ioCryoHigh AND
        t.ioCryoLow  = NEW.ioCryoLow  AND
        t.ioCryoLowAlarm = NEW.ioCryoLowAlarm AND
        t.ioCryoLiquid = NEW.ioCryoLiquid AND
        t.ioInput1 = NEW.ioInput1 AND
        t.ioInput2 = NEW.ioInput2 AND
        t.ioInput3 = NEW.ioInput3 AND
        t.ioInput4 = NEW.ioInput4 AND
        t.ioCassette1 = NEW.ioCassette1 AND
        t.ioCassette2 = NEW.ioCassette2 AND
        t.ioCassette3 = NEW.ioCassette3 AND
        t.ioCassette4 = NEW.ioCassette4 AND
        t.ioCassette5 = NEW.ioCassette5 AND
        t.ioCassette6 = NEW.ioCassette6 AND
        t.ioCassette7 = NEW.ioCassette7 AND
        t.ioCassette8 = NEW.ioCassette8 AND
        t.ioCassette9 = NEW.ioCassette9 AND
        t.ioLid1Open = NEW.ioLid1Open AND
        t.ioLid2Open = NEW.ioLid2Open AND
        t.ioLid3Open = NEW.ioLid3Open AND
        t.ioToolOpened = NEW.ioToolOpened AND
        t.ioToolClosed = NEW.ioToolClosed AND
        t.ioLimit1 = NEW.ioLimit1 AND
        t.ioLimit2 = NEW.ioLimit2 AND
        t.ioTool = NEW.ioTool AND
        t.ioToolOC = NEW.ioToolOC AND
        t.ioFast = NEW.ioFast AND
        t.ioUnlabed1 = NEW.ioUnlabed1 AND
        t.ioMagnet = NEW.ioMagnet AND
        t.ioOutput2 = NEW.ioOutput2 AND
        t.ioOutput3 = NEW.ioOutput3 AND
        t.ioOutput4 = NEW.ioOutput4 AND
        t.ioGreen = NEW.ioGreen AND
        t.ioPILZ = NEW.ioPILZ AND
        t.ioServoOn = NEW.ioServoOn AND
        t.ioServoRot = NEW.ioServoRot AND
        t.ioLN2C = NEW.ioLN2C AND
        t.ioLN2E = NEW.ioLN2E AND
        t.ioLG2E = NEW.ioLG2E AND
        t.ioHeater = NEW.ioHeater AND
        t.ioUnlabed2 = NEW.ioUnlabed2 AND
        t.ioUnlabed3 = NEW.ioUnlabed3 AND
        t.ioUnlabed4 = NEW.ioUnlabed4 AND
        t.ioUnlabed5 = NEW.ioUnlabed5
      THEN
        UPDATE cats.io SET ioTSLast = now() WHERE ioKey = t.ioKey;
        RETURN NULL;
      END IF;
    END IF;
    RETURN NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.ioInsertTF() OWNER TO lsadmin;

CREATE TRIGGER ioInsertTrigger BEFORE INSERT ON cats.io FOR EACH ROW EXECUTE PROCEDURE cats.ioInsertTF();


CREATE OR REPLACE FUNCTION  cats.setio(
       CryoOK boolean,	-- 00 Cryogen Sensors OK:  1 = OK
       ESAP   boolean,	-- 01 Emergency Stop and Air Pressure OK: 1 = OK
       CollisionOK boolean,	-- 02 Collision Sensor OK: 1 = No Collision
       CryoHighAlarm boolean, -- 03 Cryogen High Level Alarm: 1 = No Alarm
       CryoHigh boolean,	-- 04 Cryogen High Level: 1 = high level reached
       CryoLow  boolean,	-- 05 Cryogen Low Level: 1 = low level reached
       CryoLowAlarm boolean,	-- 06 Cryogen Low Level Alarm: 1 = no alarm
       CryoLiquid boolean,	-- 07 Cryogen Liquid Detection: 0=Gas, 1=Liquid
       Input1 boolean,	-- 08
       Input2 boolean,	-- 09
       Input3 boolean,	-- 10
       Input4 boolean,	-- 11
       Cassette1 boolean,	-- 12 Cassette 1 presence:  1 = cassette in place
       Cassette2 boolean,	-- 13 Cassette 2 presence:  1 = cassette in place
       Cassette3 boolean,	-- 14 Cassette 3 presence:  1 = cassette in place
       Cassette4 boolean,	-- 15 Cassette 4 presence:  1 = cassette in place
       Cassette5 boolean,	-- 16 Cassette 5 presence:  1 = cassette in place
       Cassette6 boolean,	-- 17 Cassette 6 presence:  1 = cassette in place
       Cassette7 boolean,	-- 18 Cassette 7 presence:  1 = cassette in place
       Cassette8 boolean,	-- 19 Cassette 8 presence:  1 = cassette in place
       Cassette9 boolean,	-- 20 Cassette 9 presence:  1 = cassette in place
       Lid1Open boolean,	-- 21 Lid 1 Opened: 1 = lid completely opened
       Lid2Open boolean,	-- 22 Lid 2 Opened: 1 = lid completely opened
       Lid3Open boolean,	-- 23 Lid 3 Opened: 1 = lid completely opened
       ToolOpened boolean,	-- 24 Tool Opened: 1 = tool completely opened
       ToolClosed boolean,	-- 25 Tool Closed: 1 = tool completely closed
       Limit1 boolean,	-- 26 Limit Switch 1:  0 = gripper in diffractometer position
       Limit2 boolean,	-- 27 Limit Switch 2:  0 = gripper in dewar position
       Tool boolean,		-- 28 Tool Changer:	0 = tool gripped, 1 = tool released
       ToolOC boolean,	-- 29 Tool Open/Close:  0 = tool closed, 1 = tool opened
       Fast boolean,		-- 30 Fast Output: 0 = contact open, 1 = contact closed
       Unlabed1 boolean,	-- 31 Usage not documented
       Magnet boolean,	-- 32 Output Process Information 2 [sic], Magnet ON: 0 = contact open, 1 = contact closed
       Output2 boolean,	-- 33 Output Process Information 2: 0 = contact open, 1 = contact closed
       Output3 boolean,	-- 34 Output Process Information 3: 0 = contact open, 1 = contact closed
       Output4 boolean,	-- 35 Output Process Information 4: 0 = contact open, 1 = contact closed
       Green boolean,		-- 36 Green Light (Power, air, and Modbus network OK): 1 = OK
       PILZ boolean,		-- 37 PILZ Relay Reset: 1 = reset of the relay
       ServoOn boolean,	-- 38 Servo Card ON: 1 = card on
       ServoRot boolean,	-- 39 Servo Card Rotation +/-: 0 = toard the diffractometer, 1 = toward the dewar
       LN2C boolean,		-- 40 Cryogen Valve LN2_C: 0 = closed, 1 = open
       LN2E boolean,		-- 41 Cryogen Valve LN2_E: 0 = closed, 1 = open
       LG2E boolean,		-- 42 Cryogen Valve GN2_E: 0 = closed, 1 = open
       Heater boolean,	-- 43 Heater ON/ODD: 0 = off, 1 = on
       Unlabed2 boolean,	-- 44 Usage not documented
       Unlabed3 boolean,	-- 45 Usage not documented
       Unlabed4 boolean,	-- 46 Usage not documented
       Unlabed5 boolean	-- 47 Usage not documented
) RETURNS INT AS $$
  BEGIN
    INSERT INTO cats.io (
       ioStn,           -- Our station
       ioCryoOK,	-- 00 Cryogen Sensors OK:  1 = OK
       ioESAP  ,	-- 01 Emergency Stop and Air Pressure OK: 1 = OK
       ioCollisionOK,	-- 02 Collision Sensor OK: 1 = No Collision
       ioCryoHighAlarm, -- 03 Cryogen High Level Alarm: 1 = No Alarm
       ioCryoHigh,	-- 04 Cryogen High Level: 1 = high level reached
       ioCryoLow ,	-- 05 Cryogen Low Level: 1 = low level reached
       ioCryoLowAlarm,	-- 06 Cryogen Low Level Alarm: 1 = no alarm
       ioCryoLiquid,	-- 07 Cryogen Liquid Detection: 0=Gas, 1=Liquid
       ioInput1,	-- 08
       ioInput2,	-- 09
       ioInput3,	-- 10
       ioInput4,	-- 11
       ioCassette1,	-- 12 Cassette 1 presence:  1 = cassette in place
       ioCassette2,	-- 13 Cassette 2 presence:  1 = cassette in place
       ioCassette3,	-- 14 Cassette 3 presence:  1 = cassette in place
       ioCassette4,	-- 15 Cassette 4 presence:  1 = cassette in place
       ioCassette5,	-- 16 Cassette 5 presence:  1 = cassette in place
       ioCassette6,	-- 17 Cassette 6 presence:  1 = cassette in place
       ioCassette7,	-- 18 Cassette 7 presence:  1 = cassette in place
       ioCassette8,	-- 19 Cassette 8 presence:  1 = cassette in place
       ioCassette9,	-- 20 Cassette 9 presence:  1 = cassette in place
       ioLid1Open,	-- 21 Lid 1 Opened: 1 = lid completely opened
       ioLid2Open,	-- 22 Lid 2 Opened: 1 = lid completely opened
       ioLid3Open,	-- 23 Lid 3 Opened: 1 = lid completely opened
       ioToolOpened,	-- 24 Tool Opened: 1 = tool completely opened
       ioToolClosed,	-- 25 Tool Closed: 1 = tool completely closed
       ioLimit1,	-- 26 Limit Switch 1:  0 = gripper in diffractometer position
       ioLimit2,	-- 27 Limit Switch 2:  0 = gripper in dewar position
       ioTool,		-- 28 Tool Changer:	0 = tool gripped, 1 = tool released
       ioToolOC,	-- 29 Tool Open/Close:  0 = tool closed, 1 = tool opened
       ioFast,		-- 30 Fast Output: 0 = contact open, 1 = contact closed
       ioUnlabed1,	-- 31 Usage not documented
       ioMagnet,	-- 32 Output Process Information 2 [sic], Magnet ON: 0 = contact open, 1 = contact closed
       ioOutput2,	-- 33 Output Process Information 2: 0 = contact open, 1 = contact closed
       ioOutput3,	-- 34 Output Process Information 3: 0 = contact open, 1 = contact closed
       ioOutput4,	-- 35 Output Process Information 4: 0 = contact open, 1 = contact closed
       ioGreen,		-- 36 Green Light (Power, air, and Modbus network OK): 1 = OK
       ioPILZ,		-- 37 PILZ Relay Reset: 1 = reset of the relay
       ioServoOn,	-- 38 Servo Card ON: 1 = card on
       ioServoRot,	-- 39 Servo Card Rotation +/-: 0 = toard the diffractometer, 1 = toward the dewar
       ioLN2C,		-- 40 Cryogen Valve LN2_C: 0 = closed, 1 = open
       ioLN2E,		-- 41 Cryogen Valve LN2_E: 0 = closed, 1 = open
       ioLG2E,		-- 42 Cryogen Valve GN2_E: 0 = closed, 1 = open
       ioHeater,	-- 43 Heater ON/ODD: 0 = off, 1 = on
       ioUnlabed2,	-- 44 Usage not documented
       ioUnlabed3,	-- 45 Usage not documented
       ioUnlabed4,	-- 46 Usage not documented
       ioUnlabed5	-- 47 Usage not documented
) VALUES (
       px.getStation(),		-- Our station
       CryoOK,	-- 00 Cryogen Sensors OK:  1 = OK
       ESAP  ,	-- 01 Emergency Stop and Air Pressure OK: 1 = OK
       CollisionOK,	-- 02 Collision Sensor OK: 1 = No Collision
       CryoHighAlarm, -- 03 Cryogen High Level Alarm: 1 = No Alarm
       CryoHigh,	-- 04 Cryogen High Level: 1 = high level reached
       CryoLow ,	-- 05 Cryogen Low Level: 1 = low level reached
       CryoLowAlarm,	-- 06 Cryogen Low Level Alarm: 1 = no alarm
       CryoLiquid,	-- 07 Cryogen Liquid Detection: 0=Gas, 1=Liquid
       Input1,	-- 08
       Input2,	-- 09
       Input3,	-- 10
       Input4,	-- 11
       Cassette1,	-- 12 Cassette 1 presence:  1 = cassette in place
       Cassette2,	-- 13 Cassette 2 presence:  1 = cassette in place
       Cassette3,	-- 14 Cassette 3 presence:  1 = cassette in place
       Cassette4,	-- 15 Cassette 4 presence:  1 = cassette in place
       Cassette5,	-- 16 Cassette 5 presence:  1 = cassette in place
       Cassette6,	-- 17 Cassette 6 presence:  1 = cassette in place
       Cassette7,	-- 18 Cassette 7 presence:  1 = cassette in place
       Cassette8,	-- 19 Cassette 8 presence:  1 = cassette in place
       Cassette9,	-- 20 Cassette 9 presence:  1 = cassette in place
       Lid1Open,	-- 21 Lid 1 Opened: 1 = lid completely opened
       Lid2Open,	-- 22 Lid 2 Opened: 1 = lid completely opened
       Lid3Open,	-- 23 Lid 3 Opened: 1 = lid completely opened
       ToolOpened,	-- 24 Tool Opened: 1 = tool completely opened
       ToolClosed,	-- 25 Tool Closed: 1 = tool completely closed
       Limit1,	-- 26 Limit Switch 1:  0 = gripper in diffractometer position
       Limit2,	-- 27 Limit Switch 2:  0 = gripper in dewar position
       Tool,		-- 28 Tool Changer:	0 = tool gripped, 1 = tool released
       ToolOC,	-- 29 Tool Open/Close:  0 = tool closed, 1 = tool opened
       Fast,		-- 30 Fast Output: 0 = contact open, 1 = contact closed
       Unlabed1,	-- 31 Usage not documented
       Magnet,	-- 32 Output Process Information 2 [sic], Magnet ON: 0 = contact open, 1 = contact closed
       Output2,	-- 33 Output Process Information 2: 0 = contact open, 1 = contact closed
       Output3,	-- 34 Output Process Information 3: 0 = contact open, 1 = contact closed
       Output4,	-- 35 Output Process Information 4: 0 = contact open, 1 = contact closed
       Green,		-- 36 Green Light (Power, air, and Modbus network OK): 1 = OK
       PILZ,		-- 37 PILZ Relay Reset: 1 = reset of the relay
       ServoOn,	-- 38 Servo Card ON: 1 = card on
       ServoRot,	-- 39 Servo Card Rotation +/-: 0 = toard the diffractometer, 1 = toward the dewar
       LN2C,		-- 40 Cryogen Valve LN2_C: 0 = closed, 1 = open
       LN2E,		-- 41 Cryogen Valve LN2_E: 0 = closed, 1 = open
       LG2E,		-- 42 Cryogen Valve GN2_E: 0 = closed, 1 = open
       Heater,	-- 43 Heater ON/ODD: 0 = off, 1 = on
       Unlabed2,	-- 44 Usage not documented
       Unlabed3,	-- 45 Usage not documented
       Unlabed4,	-- 46 Usage not documented
       Unlabed5	-- 47 Usage not documented
);

  RETURN 1;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setio( 
       CryoOK boolean,	-- 00 Cryogen Sensors OK:  1 = OK
       ESAP   boolean,	-- 01 Emergency Stop and Air Pressure OK: 1 = OK
       CollisionOK boolean,	-- 02 Collision Sensor OK: 1 = No Collision
       CryoHighAlarm boolean, -- 03 Cryogen High Level Alarm: 1 = No Alarm
       CryoHigh boolean,	-- 04 Cryogen High Level: 1 = high level reached
       CryoLow  boolean,	-- 05 Cryogen Low Level: 1 = low level reached
       CryoLowAlarm boolean,	-- 06 Cryogen Low Level Alarm: 1 = no alarm
       CryoLiquid boolean,	-- 07 Cryogen Liquid Detection: 0=Gas, 1=Liquid
       Input1 boolean,	-- 08
       Input2 boolean,	-- 09
       Input3 boolean,	-- 10
       Input4 boolean,	-- 11
       Cassette1 boolean,	-- 12 Cassette 1 presence:  1 = cassette in place
       Cassette2 boolean,	-- 13 Cassette 2 presence:  1 = cassette in place
       Cassette3 boolean,	-- 14 Cassette 3 presence:  1 = cassette in place
       Cassette4 boolean,	-- 15 Cassette 4 presence:  1 = cassette in place
       Cassette5 boolean,	-- 16 Cassette 5 presence:  1 = cassette in place
       Cassette6 boolean,	-- 17 Cassette 6 presence:  1 = cassette in place
       Cassette7 boolean,	-- 18 Cassette 7 presence:  1 = cassette in place
       Cassette8 boolean,	-- 19 Cassette 8 presence:  1 = cassette in place
       Cassette9 boolean,	-- 20 Cassette 9 presence:  1 = cassette in place
       Lid1Open boolean,	-- 21 Lid 1 Opened: 1 = lid completely opened
       Lid2Open boolean,	-- 22 Lid 2 Opened: 1 = lid completely opened
       Lid3Open boolean,	-- 23 Lid 3 Opened: 1 = lid completely opened
       ToolOpened boolean,	-- 24 Tool Opened: 1 = tool completely opened
       ToolClosed boolean,	-- 25 Tool Closed: 1 = tool completely closed
       Limit1 boolean,	-- 26 Limit Switch 1:  0 = gripper in diffractometer position
       Limit2 boolean,	-- 27 Limit Switch 2:  0 = gripper in dewar position
       Tool boolean,		-- 28 Tool Changer:	0 = tool gripped, 1 = tool released
       ToolOC boolean,	-- 29 Tool Open/Close:  0 = tool closed, 1 = tool opened
       Fast boolean,		-- 30 Fast Output: 0 = contact open, 1 = contact closed
       Unlabed1 boolean,	-- 31 Usage not documented
       Magnet boolean,	-- 32 Output Process Information 2 [sic], Magnet ON: 0 = contact open, 1 = contact closed
       Output2 boolean,	-- 33 Output Process Information 2: 0 = contact open, 1 = contact closed
       Output3 boolean,	-- 34 Output Process Information 3: 0 = contact open, 1 = contact closed
       Output4 boolean,	-- 35 Output Process Information 4: 0 = contact open, 1 = contact closed
       Green boolean,		-- 36 Green Light (Power, air, and Modbus network OK): 1 = OK
       PILZ boolean,		-- 37 PILZ Relay Reset: 1 = reset of the relay
       ServoOn boolean,	-- 38 Servo Card ON: 1 = card on
       ServoRot boolean,	-- 39 Servo Card Rotation +/-: 0 = toard the diffractometer, 1 = toward the dewar
       LN2C boolean,		-- 40 Cryogen Valve LN2_C: 0 = closed, 1 = open
       LN2E boolean,		-- 41 Cryogen Valve LN2_E: 0 = closed, 1 = open
       LG2E boolean,		-- 42 Cryogen Valve GN2_E: 0 = closed, 1 = open
       Heater boolean,	-- 43 Heater ON/ODD: 0 = off, 1 = on
       Unlabed2 boolean,	-- 44 Usage not documented
       Unlabed3 boolean,	-- 45 Usage not documented
       Unlabed4 boolean,	-- 46 Usage not documented
       Unlabed5 boolean	-- 47 Usage not documented
) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.setIO() returns void as $$
  DECLARE
    k bigint;
  BEGIN
    SELECT ioKey INTO k FROM cats.io WHERE ioStn=px.getStation() ORDER BY ioTSLast DESC LIMIT 1;
    IF FOUND THEN
      UPDATE cats.io SET ioTSLast = now() WHERE ioKey=k;
    END IF;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setIO() OWNER TO lsadmin;


CREATE TABLE cats.positions (
       pKey serial primary key,
       pTSStart timestamp with time zone default now(),
       pTSLast  timestamp with time zone default now(),
       pStn bigint references px.stations (stnkey),

       pX numeric(20,6),
       pY numeric(20,6),
       pZ numeric(20,6),
       pRX numeric(20,6),
       pRY numeric(20,6),
       pRZ numeric(20,6)
);
ALTER TABLE cats.positions OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.positionsInsertTF() returns trigger as $$
  DECLARE
    t record;
  BEGIN
    SELECT * INTO t FROM cats.positions WHERE pStn=px.getStation() ORDER BY pTSLast DESC LIMIT 1;
    IF FOUND THEN
      IF
        t.pX = NEW.pX AND
        t.pY = NEW.pY AND
        t.pZ = NEW.pZ AND
        t.pRX = NEW.pRX AND
        t.pRY = NEW.pRY AND
        t.pRZ = NEW.pRZ
      THEN
        UPDATE cats.positions SET pTSLast = now() WHERE pKey = t.pKey;
        RETURN NULL;
      END IF;
    END IF;
    DELETE FROM cats.positions WHERE pStn=px.getStation();
   RETURN NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.positionsInsertTF() OWNER TO lsadmin;

#CREATE TRIGGER positionsInsertTrigger BEFORE INSERT ON cats.positions FOR EACH ROW EXECUTE PROCEDURE cats.positionsInsertTF();

CREATE OR REPLACE FUNCTION cats.setposition( x numeric(20,6), y numeric(20,6), z numeric(20,6), rx numeric(20,6), ry numeric(20,6), rz numeric(20,6)) returns int as $$
  BEGIN
    INSERT INTO cats.positions ( pStn, pX, pY, pZ, pRX, pRY, pRZ) VALUES ( px.getStation(), x, y, z, rx, ry, rz);
    RETURN 1;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setposition( numeric(20,6), numeric(20,6), numeric(20,6), numeric(20,6), numeric(20,6), numeric(20,6)) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.setPosition() returns void as $$
  DECLARE
    k bigint;
  BEGIN
    SELECT pKey INTO k FROM cats.positions WHERE pStn = px.getStation() ORDER BY pTSLast LIMIT 1;
    IF FOUND THEN
      UPDATE cats.positions SET pTSLast = now() WHERE pKey = k;
    END IF;
    RETURN;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setPosition() OWNER TO lsadmin;


CREATE TABLE cats.diffPos(
-- Diffactometer position
       dpKey serial primary key,
       dpTs timestamp with time zone,
       dpStn bigint references px.stations (stnkey),
       dpX numeric(20,6),
       dpY numeric(20,6),
       dpZ numeric(20,6),
);
ALTER TABLE cats.diffpos OWNER TO lsadmin;
GRANT SELECT ON cats.diffpos TO PUBLIC;

CREATE OR REPLACE FUNCTION cats.tooclose() returns boolean as $$
  SELECT ((pX-dpX)*(pX-dpX)+(pY-dpY)*(py-dpY)+(pZ-dpZ)*(pZ-dpZ)) < 9.0E4 FROM cats.positions left join cats.diffPos on dpStn=pStn WHERE dpStn=px.getStation() order by pkey desc, dpkey desc limit 1;
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.tooclose() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.tooclose( theStn bigint) returns boolean as $$
  SELECT ((pX-dpX)*(pX-dpX)+(pY-dpY)*(py-dpY)+(pZ-dpZ)*(pZ-dpZ)) < 9.0E4 FROM cats.positions left join cats.diffPos on dpStn=pStn WHERE pstn=$1 order by pkey desc limit 1;
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.tooclose(bigint) OWNER TO lsadmin;


CREATE TABLE cats.messages (
       mKey serial primary key,
       mTSStart timestamp with time zone default now(),
       mTSLast timestamp with time zone default now(),
       mStn bigint references px.stations (stnkey),
       mmsg text
);
ALTER TABLE cats.messages OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.messagesInsertTF() returns trigger as $$
  DECLARE
    t record;
  BEGIN
    SELECT * INTO t FROM cats.messages WHERE mStn=px.getStation() ORDER BY mTSLast DESC LIMIT 1;
    IF FOUND THEN
      IF t.mmsg = NEW.mmsg THEN
        UPDATE cats.messages SET mTSLast = now() WHERE mKey = t.mKey;
        RETURN NULL;
      END IF;
    END IF;
    RETURN NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.messagesInsertTF() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.setmessage( msg text) returns int as $$
  BEGIN
    INSERT INTO cats.messages (mStn, mmsg) VALUES (px.getStation(), msg);
    RETURN 1;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.setmessage( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.setMessage() returns void as $$
  DECLARE
    k bigint;
  BEGIN
    SELECT mKey INTO k FROM cats.messages WHERE mStn=px.getStation() ORDER BY mTSLast DESC LIMIT 1;
    IF FOUND THEN
      UPDATE cats.messages SET mTSLast = now() WHERE mKey = k;
    END IF;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

ALTER FUNCTION cats.setMessage() OWNER TO lsadmin;


CREATE TABLE cats._queue (
       qKey serial primary key,		-- our key
       qts timestamp with time zone not null default now(),
       qaddr inet not null,		-- IP address of catsOK routine
       qCmd text not null,		-- the command
       qStart timestamp with time zone not null default now(),	-- Don't start before this time
       qPath text default null,		-- the path (used for timing)
       qTool int  default null		-- the tool to be used (for timing)
);
ALTER TABLE cats._queue OWNER TO lsadmin;
       
CREATE OR REPLACE FUNCTION cats._pushqueue( cmd text) RETURNS VOID AS $$
  SELECT cats._pushqueue( $1, now(), NULL, NULL);
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats._pushqueue( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats._pushqueue( theStn bigint, cmd text) RETURNS VOID AS $$
  SELECT cats._pushqueue( $1, $2, now(), NULL, NULL);
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats._pushqueue( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats._clearqueue( theStn int) RETURNS VOID AS $$
  DECLARE
    theRobot inet;
  BEGIN
    SELECT INTO theRobot crobot FROM px._config WHERE cstnkey = theStn;
    DELETE FROM cats._queue WHERE qaddr = theRobot;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats._clearqueue( int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats._pushqueue( theStn bigint, cmd text, startTime timestamp with time zone, thePath text, theTool int) RETURNS VOID AS $$
  DECLARE
    c text;	    -- trimmed command
    ntfy text;	    -- used to generate notify command
    theRobot inet;  -- address of CatsOk routine
  BEGIN
    SELECT cnotifyrobot, crobot INTO ntfy, theRobot FROM px._config LEFT JOIN px.stations ON cstation=stnname WHERE stnkey=theStn;
    IF NOT FOUND THEN
      RETURN;
    END IF;
    c := trim( cmd);
    IF length( c) > 0 THEN
      --
      -- Delete remaining commands in the queue during an abort or panic
      IF lower(c) = 'abort' or lower(c) = 'panic'  THEN
        DELETE FROM cats._queue WHERE qaddr = theRobot;
      END IF;

      --
      -- replace NULL start with now
      IF startTime is null THEN
        INSERT INTO cats._queue (qcmd, qaddr, qpath, qtool) VALUES (c, theRobot, thePath, theTool);
      ELSE
        INSERT INTO cats._queue (qcmd, qaddr, qStart, qpath, qtool) VALUES (c, theRobot, startTime, thePath, theTool);
      END IF;


      IF FOUND THEN
        EXECUTE 'NOTIFY ' || ntfy;
      ELSE
        RAISE EXCEPTION 'Client is not associated with a robot: %', inet_client_addr();
      END IF;
    END IF;
    RETURN;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats._pushqueue( text, timestamp with time zone, text, int) OWNER TO lsadmin;

drop type cats.popqueuetype cascade;

CREATE TYPE cats.popqueuetype AS (cmd text, startEpoch float, pqpath text, pqtool int);

CREATE OR REPLACE FUNCTION cats._popqueue() RETURNS cats.popqueuetype AS $$
  DECLARE
    rtn cats.popqueuetype;	-- return value
    qk   bigint;		-- queue key of item
  BEGIN
    rtn.cmd := '';
    SELECT   qCmd,    qKey, extract(epoch from qStart)::float, qpath,      qtool
        INTO rtn.cmd, qk,   rtn.startEpoch,                    rtn.pqpath, rtn.pqtool
        FROM cats._queue
        WHERE qaddr=inet_client_addr()
        ORDER BY qKey ASC LIMIT 1;
    IF NOT FOUND THEN
      rtn.cmd       := '';
      rtn.startEpoch := NULL;
      return rtn;
    END IF;
    DELETE FROM cats._queue WHERE qKey=qk;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats._popqueue() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.init() RETURNS VOID AS $$
  --
  -- Called by process controlling the robot
  --
  DECLARE
    ntfy text;
  BEGIN
    DELETE FROM cats._queue WHERE qaddr = inet_client_addr();    
    SELECT cnotifyrobot INTO ntfy FROM px._config WHERE cstnkey=px.getstation();
    IF FOUND THEN
       EXECUTE 'LISTEN ' || ntfy;
    END IF;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.init() OWNER TO lsadmin;


CREATE TABLE cats._acmds (
	-- CATS commands that require an argument
       ac text primary key
);
INSERT INTO cats._acmds (ac) VALUES ('backup');
INSERT INTO cats._acmds (ac) VALUES ('restore');
INSERT INTO cats._acmds (ac) VALUES ('home');
INSERT INTO cats._acmds (ac) VALUES ('safe');
INSERT INTO cats._acmds (ac) VALUES ('reference');
INSERT INTO cats._acmds (ac) VALUES ('put');
INSERT INTO cats._acmds (ac) VALUES ('put_bcrd');
INSERT INTO cats._acmds (ac) VALUES ('get');
INSERT INTO cats._acmds (ac) VALUES ('get_bcrd');
INSERT INTO cats._acmds (ac) VALUES ('getput');
INSERT INTO cats._acmds (ac) VALUES ('getput_bcrd');
INSERT INTO cats._acmds (ac) VALUES ('barcode');
INSERT INTO cats._acmds (ac) VALUES ('transfer');
INSERT INTO cats._acmds (ac) VALUES ('soak');
INSERT INTO cats._acmds (ac) VALUES ('dry');
INSERT INTO cats._acmds (ac) VALUES ('putplate');
INSERT INTO cats._acmds (ac) VALUES ('getplate');
INSERT INTO cats._acmds (ac) VALUES ('getputplate');
INSERT INTO cats._acmds (ac) VALUES ('goto_well');
INSERT INTO cats._acmds (ac) VALUES ('adjust');
INSERT INTO cats._acmds (ac) VALUES ('focus');
INSERT INTO cats._acmds (ac) VALUES ('expose');
INSERT INTO cats._acmds (ac) VALUES ('collect');
INSERT INTO cats._acmds (ac) VALUES ('setplateangle');


CREATE TABLE cats._args (
       -- Used to generate argument lists for CATS control functions
       aKey serial primary key,
       aTS timestamp with time zone default now(),
       aCmd text NOT NULL references cats._acmds (ac) on update cascade,	-- here are the legal commands       
       aCap int default 0,		-- USB port or tool number
       aLid int default 0,		-- lid number (AKA dewar nuber)
       aSample int default 0,		-- sample number within dewar
       aNewLid int default 0,		-- new lid to which to transfer sample
       aNewSample int default 0,	-- new sample position to transfer to
       aXtalPlate int default 0,	-- Crystallization plate number
       aWell int default 0,		-- number of well to go to
       aArg7 int default 0,		-- spare argument
       aArg8 int default 0,		-- spare argument
       aArg9 int default 0,		-- spare argument
       aXShift float default 0.0,	-- X offset
       aYShift float default 0.0,	-- Y offset
       aZShift float default 0.0,	-- Z offset
       aAngle float default 0.0,	-- Angle
       aOscs int default 0,		-- number of oscillations
       aExp float default 0.0,		-- exposure time
       aStep float default 0.0,		-- angular step
       aFinal float default 0.0,	-- Final Angle
       aArg18 int default 0,		-- spare argument
       aArg19 int default 0		-- spare argument
);
ALTER TABLE cats._args OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats._gencmd( k bigint) returns text as $$
  DECLARE
    rtn text;
  BEGIN
    rtn := '';
    SELECT aCmd || '(' || aCap || ',' || aLid || ',' || aSample || ',' || aNewLid || ',' || aNewSample || ',' ||
        aXtalPlate || ',' || aWell || ',' || aArg7 || ',' || aArg8 || ',' || aArg9 || ',' || 
        aXShift || ',' || aYShift || ',' || aZShift || ',' || aAngle || ',' || 
        aOscs || ',' || aExp || ',' || aStep || ',' || aFinal || ',' || aArg18 || ',' || aArg19 || ')'
      INTO rtn
      FROM cats._args
      WHERE aKey = k;
    IF FOUND THEN
      DELETE FROM cats._args WHERE aKey=k;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats._gencmd( bigint) OWNER TO lsadmin;

CREATE TABLE cats._cylinder2tool (
       ctKey serial primary key,	-- our primary key
       ctcyl int unique,		-- our normalized cylinder number (1-255) Must be unique as we'll expect one and only one row give a cylinder number
       ctoff int,			-- offset to a zero based cylinder number (0-2)
       ctnsamps int,			-- number of sample positions in this cylinder
       cttoolno int,			-- the CATS tool number needed to access this cylinder
       cttoolname text			-- the name of the corresponding CATS tool (control requires number, status replies with name)
);
ALTER TABLE cats._cylinder2tool OWNER TO lsadmin;

INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  1,  1, 10, 1, 'SPINE');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  2,  1, 10, 1, 'SPINE');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  3,  1, 10, 1, 'SPINE');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  4,  4, 12, 3, 'Rigaku');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  5,  4, 12, 3, 'Rigaku');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  6,  4, 12, 3, 'Rigaku');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  7,  7, 16, 4, 'ALS');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  8,  7, 16, 4, 'ALS');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES (  9,  7, 16, 4, 'ALS');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES ( 10, 10, 16, 5, 'UNI');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES ( 11, 10, 16, 5, 'UNI');
INSERT INTO cats._cylinder2tool (ctcyl, ctoff, ctnsamps, cttoolno, cttoolname) VALUES ( 12, 10, 16, 5, 'UNI');

CREATE TABLE cats._toolCorrection (
       tckey serial primary key,
       tcstn bigint references px.stations (stnkey),
       tcts  timestamp with time zone default now(),
       tcTool int not null default 0,
       tcX int not null default 0,
       tcY int not null default 0,
       tcZ int not null default 0
);
ALTER TABLE cats._toolCorrection OWNER TO lsadmin;

CREATE TABLE cats._toolTiming (
--
-- Catalog of times needed from the start of a path to the requirement for airrights
--
       ttkey serial primary key,
       ttstn bigint references px.stations (stnkey),
       ttTool int not null default 0,
       ttPath text not null default '',
       ttair interval not null default '0'::interval,  -- time to air rights needed
       ttchkmag interval not null default '0'::interval, -- time to check smart magnet state
       ttnoair interval not null default '0'::interval, -- time to no air rights needed
       ttdone  interval not null default '0'::interval  -- time until 'done'  (finished drying for get, ttnoair otherwise
);
ALTER TABLE cats._toolTiming OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats._mkcryocmd( theCmd text, theId int, theNewId int, xx int, yy int, zz int) RETURNS INT AS $$
  SELECT cats._mkcryocmd( $1, $2, $3, $4, $5, $6, 0.0::numeric);
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats._mkcryocmd( text, int, int, int, int, int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats._mkcryocmd( theStn bigint, theCmd text, theId int, theNewId int, xx int, yy int, zz int) RETURNS INT AS $$
  SELECT cats._mkcryocmd( $1, $2, $3, $4, $5, $6, $7, 0.0::numeric);
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats._mkcryocmd( bigint, text, int, int, int, int, int) OWNER TO lsadmin;




CREATE OR REPLACE FUNCTION cats._mkcryocmd( theCmd text, theId int, theNewId int, xx int, yy int, zz int, esttime numeric) RETURNS INT AS $$
  --
  -- All the cryocrystallography commands have very similar requirements
  -- This is a low level function to service the put, get, (and getput), as well as the brcd flavors
  -- Also, the barcode, transfer, soak, dry, home, safe, and reference commands are supported here
  --
  -- esttime is the number of seconds before we'll likely be able to get the air rights
  -- used to calculate the time parameter for the command
  --
  DECLARE
    rtn int;	-- return: 1 on success, 0 on failure

    ison boolean;  -- true when the robot is "on"
	--
	-- Convert theId so something the robot can use
    cstn1 int;	-- control system's station number
    cdwr1 int;	-- control system's dewar number
    ccyl1 int;	-- control system's cylinder number
    csmp1 int;	-- control system's sample number
    rlid1 int;	-- robot's lid number
    rtool1 int;	-- robot's tool number
    rsmpl1 int;	-- robot's sample number

    cstn2 int;	-- control system's station number
    cdwr2 int;	-- control system's dewar number
    ccyl2 int;	-- control system's cylinder number
    csmp2 int;	-- control system's sample number
    rlid2 int;	-- robot's lid number
    rtool2 int;	-- robot's tool number
    rsmpl2 int;	-- robot's sample number

    startTime timestamp with time zone;
    tc record;  -- tool correction: a kludge to finetune the diffractometer position

  BEGIN
    rtn := 0;

    SELECT cspower INTO ison FROM cats.states WHERE csstn=px.getStation() ORDER BY csKey DESC LIMIT 1;
    IF FOUND and not ison THEN
      PERFORM cats._pushqueue( 'on');
    END IF;    

    INSERT INTO cats._args (aCmd) VALUES ( theCmd);

    --
    -- theId is zero for an "get".  Here we need to get the tool number from the current state
    --
    IF theId = 0 THEN
      SELECT cttoolno INTO rtool1 FROM cats.states LEFT JOIN cats._cylinder2tool ON ctToolName=csToolNumber WHERE csstn=px.getStation() ORDER BY csKey desc LIMIT 1;
      IF FOUND THEN
        UPDATE cats._args SET aCap=rtool1 WHERE aKey=currval('cats._args_akey_seq');
      END IF;
    END IF;

    IF theId != 0 THEN
      --
      -- Pick out the control system's numbers
      -- home, safe, get, soak, and dry need at least an ID corresponding to a cylinder to choose the right tool
      --
      cstn1 := (theId & x'ff000000'::int) >> 24;
      cdwr1 := (theId & x'00ff0000'::int) >> 16;
      ccyl1 := (theId & x'0000ff00'::int) >>  8;
      csmp1 :=  theId & x'000000ff'::int;
      --
      -- Find the Robot's numbers
      --
      -- 1 = current tool, 2 = diffractometer, 3-5 = lids
      -- For now only allow references to lid positions in the CATS dewar
      IF cdwr1 < 3 or cdwr1 > 5 THEN
        return 0;
      END IF;
      rlid1 := cdwr1 - 2;

      SELECT cttoolno, (ccyl1-ctoff)*ctnsamps + csmp1 INTO rtool1, rsmpl1 FROM cats._cylinder2tool WHERE ctcyl=ccyl1;
      IF NOT FOUND THEN
        return 0;
      END IF;
      -- Now we know what we want
      UPDATE cats._args SET aCap=rtool1, aLid=rlid1, aSample=rsmpl1 WHERE akey=currval('cats._args_akey_seq');
    END IF;

    IF theId != 0 and theNewId != 0 THEN
      --
      -- Pick out the control system's numbers
      --
      cstn2 := (theNewId & x'ff000000'::int) >> 24;
      cdwr2 := (theNewId & x'00ff0000'::int) >> 16;
      ccyl2 := (theNewId & x'0000ff00'::int) >>  8;
      csmp2 :=  theNewId & x'000000ff'::int;
      --
      -- Find the Robot's numbers
      --
      -- 1 = current tool, 2 = diffractometer, 3-5 = lids
      -- For now only allow reference to position in the CATS dewar
      IF cdwr2 < 3 or cdwr2 > 5 THEN
        return 0;
      END IF;
      rlid2 := cdwr2 - 2;

      SELECT cttoolno, (ccyl2-ctoff)*ctnsamps + csmp2 INTO rtool2, rsmpl2 FROM cats._cylinder2tool WHERE ctcyl=ccyl2;
      IF NOT FOUND OR rtool1 != rtool2 THEN
        return 0;
      END IF;
      -- Now we know what we want
      UPDATE cats._args SET aNewLid=rlid2, aNewSample=rsmpl2 WHERE akey=currval('cats._args_akey_seq');
    END IF;


    --
    -- Get the diffractometer correction
    --
    SELECT * INTO tc FROM cats._toolCorrection WHERE tcstn=px.getStation() and tcTool = rtool1 ORDER BY tcKey DESC LIMIT 1;
    IF FOUND THEN
    -- set the diffractometer correction additionally corrected
      UPDATE cats._args SET aXShift = xx + tc.tcx, aYShift = yy + tc.tcy, aZShift = zz + tc.tcz WHERE aKey=currval('cats._args_akey_seq');
    ELSE
    -- set the diffractometer correction not additionally corrected
      UPDATE cats._args SET aXShift = xx, aYShift = yy, aZShift = zz WHERE aKey=currval('cats._args_akey_seq');
    END IF;

    --
    -- get a start time based on esttime parameter
    -- The esttime is the approximate time that the diffractometer will give up the air rights
    -- We'll plan to delay our start so that we first request air rights just after the diffractometer gives them up
    --
    Select CASE WHEN extract( epoch from ttair) < esttime
                THEN to_timestamp( extract( epoch from now()) + esttime - extract( epoch from ttair))
                ELSE now() END
                INTO startTime
                FROM cats._tooltiming
                WHERE ttstn=px.getStation() and tttool=rtool1 and ttpath=thecmd;
    IF NOT FOUND THEN
      -- No timing available: just start right away
      startTime := now();
    END IF;

    -- add path to the queue
    PERFORM cats._pushqueue( cats._gencmd( currval( 'cats._args_akey_seq')), startTime, theCmd, rtool1);

    -- update our current path for printing out busy bar
    INSERT INTO cats.curpath (cpts,cptool, cpstn, cppath) VALUES( startTime, rtool1, px.getstation(), theCmd);
    return 1;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats._mkcryocmd( text, int, int, int, int, int, numeric) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats._mkcryocmd( theStn bigint, theCmd text, theId int, theNewId int, xx int, yy int, zz int, esttime numeric) RETURNS INT AS $$
  --
  -- All the cryocrystallography commands have very similar requirements
  -- This is a low level function to service the put, get, (and getput), as well as the brcd flavors
  -- Also, the barcode, transfer, soak, dry, home, safe, and reference commands are supported here
  --
  -- esttime is the number of seconds before we'll likely be able to get the air rights
  -- used to calculate the time parameter for the command
  --
  DECLARE
    rtn int;	-- return: 1 on success, 0 on failure

    ison boolean;  -- true when the robot is "on"
	--
	-- Convert theId so something the robot can use
    cstn1 int;	-- control system's station number
    cdwr1 int;	-- control system's dewar number
    ccyl1 int;	-- control system's cylinder number
    csmp1 int;	-- control system's sample number
    rlid1 int;	-- robot's lid number
    rtool1 int;	-- robot's tool number
    rsmpl1 int;	-- robot's sample number

    cstn2 int;	-- control system's station number
    cdwr2 int;	-- control system's dewar number
    ccyl2 int;	-- control system's cylinder number
    csmp2 int;	-- control system's sample number
    rlid2 int;	-- robot's lid number
    rtool2 int;	-- robot's tool number
    rsmpl2 int;	-- robot's sample number

    startTime timestamp with time zone;
    tc record;  -- tool correction: a kludge to finetune the diffractometer position

  BEGIN
    rtn := 0;

    SELECT cspower INTO ison FROM cats.states WHERE csstn=theStn ORDER BY csKey DESC LIMIT 1;
    IF FOUND and not ison THEN
      PERFORM cats._pushqueue( theStn, 'on');
    END IF;    

    INSERT INTO cats._args (aCmd) VALUES ( theCmd);

    --
    -- theId is zero for an "get".  Here we need to get the tool number from the current state
    --
    IF theId = 0 THEN
      SELECT cttoolno INTO rtool1 FROM cats.states LEFT JOIN cats._cylinder2tool ON ctToolName=csToolNumber WHERE csstn=theStn ORDER BY csKey desc LIMIT 1;
      IF FOUND THEN
        UPDATE cats._args SET aCap=rtool1 WHERE aKey=currval('cats._args_akey_seq');
      END IF;
    END IF;

    IF theId != 0 THEN
      --
      -- Pick out the control system's numbers
      -- home, safe, get, soak, and dry need at least an ID corresponding to a cylinder to choose the right tool
      --
      cstn1 := (theId & x'ff000000'::int) >> 24;
      cdwr1 := (theId & x'00ff0000'::int) >> 16;
      ccyl1 := (theId & x'0000ff00'::int) >>  8;
      csmp1 :=  theId & x'000000ff'::int;
      --
      -- Find the Robot's numbers
      --
      -- 1 = current tool, 2 = diffractometer, 3-5 = lids
      -- For now only allow references to lid positions in the CATS dewar
      IF cdwr1 < 3 or cdwr1 > 5 THEN
        return 0;
      END IF;
      rlid1 := cdwr1 - 2;

      SELECT cttoolno, (ccyl1-ctoff)*ctnsamps + csmp1 INTO rtool1, rsmpl1 FROM cats._cylinder2tool WHERE ctcyl=ccyl1;
      IF NOT FOUND THEN
        return 0;
      END IF;
      -- Now we know what we want
      UPDATE cats._args SET aCap=rtool1, aLid=rlid1, aSample=rsmpl1 WHERE akey=currval('cats._args_akey_seq');
    END IF;

    IF theId != 0 and theNewId != 0 THEN
      --
      -- Pick out the control system's numbers
      --
      cstn2 := (theNewId & x'ff000000'::int) >> 24;
      cdwr2 := (theNewId & x'00ff0000'::int) >> 16;
      ccyl2 := (theNewId & x'0000ff00'::int) >>  8;
      csmp2 :=  theNewId & x'000000ff'::int;
      --
      -- Find the Robot's numbers
      --
      -- 1 = current tool, 2 = diffractometer, 3-5 = lids
      -- For now only allow reference to position in the CATS dewar
      IF cdwr2 < 3 or cdwr2 > 5 THEN
        return 0;
      END IF;
      rlid2 := cdwr2 - 2;

      SELECT cttoolno, (ccyl2-ctoff)*ctnsamps + csmp2 INTO rtool2, rsmpl2 FROM cats._cylinder2tool WHERE ctcyl=ccyl2;
      IF NOT FOUND OR rtool1 != rtool2 THEN
        return 0;
      END IF;
      -- Now we know what we want
      UPDATE cats._args SET aNewLid=rlid2, aNewSample=rsmpl2 WHERE akey=currval('cats._args_akey_seq');
    END IF;


    --
    -- Get the diffractometer correction
    --
    SELECT * INTO tc FROM cats._toolCorrection WHERE tcstn=theStn and tcTool = rtool1 ORDER BY tcKey DESC LIMIT 1;
    IF FOUND THEN
    -- set the diffractometer correction additionally corrected
      UPDATE cats._args SET aXShift = xx + tc.tcx, aYShift = yy + tc.tcy, aZShift = zz + tc.tcz WHERE aKey=currval('cats._args_akey_seq');
    ELSE
    -- set the diffractometer correction not additionally corrected
      UPDATE cats._args SET aXShift = xx, aYShift = yy, aZShift = zz WHERE aKey=currval('cats._args_akey_seq');
    END IF;

    --
    -- get a start time based on esttime parameter
    -- The esttime is the approximate time that the diffractometer will give up the air rights
    -- We'll plan to delay our start so that we first request air rights just after the diffractometer gives them up
    --
    SELECT CASE WHEN extract( epoch from ttair) < esttime
                THEN to_timestamp( extract( epoch from now()) + esttime - extract( epoch from ttair))
                ELSE now() END
                INTO startTime
                FROM cats._tooltiming
                WHERE ttstn=theStn and tttool=rtool1 and ttpath=thecmd;
    IF NOT FOUND THEN
      -- No timing available: just start right away
      startTime := now();
    END IF;

    -- add path to the queue
    PERFORM cats._pushqueue( theStn, cats._gencmd( currval( 'cats._args_akey_seq')), startTime, theCmd, rtool1);

    -- update our current path for printing out busy bar
    INSERT INTO cats.curpath (cpts,cptool, cpstn, cppath) VALUES( startTime, rtool1, theStn,  theCmd);
    return 1;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats._mkcryocmd( bigint, text, int, int, int, int, int, numeric) OWNER TO lsadmin;

CREATE TABLE cats.curpath(
  cpkey serial primary key,   -- our key
  cpts timestamp with time zone default now(),
  cpdoneTime timestamp with time zone default now()+'00:00:02',
  cptool int,		      -- current tool
  cpstn  bigint not null,     -- referneces px.stations (stnkey),
  cppath text
);
ALTER TABLE cats.curpath OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.curpathInsertTF() returns trigger AS $$
  DECLARE
   cp record;
   doneTime timestamp with time zone;
  BEGIN
    SELECT NEW.cpts + ttnoair INTO doneTime FROM cats._tooltiming WHERE NEW.cptool=tttool and NEW.cppath=ttpath and NEW.cpstn=ttstn;
    IF FOUND THEN
        NEW.cpdoneTime := doneTime;
    END IF;
    DELETE FROM cats.curpath WHERE cpkey<NEW.cpkey and cpstn=NEW.cpstn;
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.curpathInsertTF() OWNER TO lsadmin;
CREATE TRIGGER curpathInsertTrigger BEFORE INSERT ON cats.curpath FOR EACH ROW EXECUTE PROCEDURE cats.curpathInsertTF();

CREATE OR REPLACE FUNCTION cats.fractionDone() returns float as $$
  DECLARE
    rtn float;
    cp record;
  BEGIN
    SELECT extract( epoch from (now() - cpts))/(0.1+abs(extract( epoch from (cpdonetime-cpts)))) INTO rtn FROM cats.curpath WHERE cpstn=px.getstation() ORDER BY cpkey desc LIMIT 1;
    IF NOT FOUND OR rtn > 1.0 THEN
      rtn := 1.0;
    END IF;
    IF rtn < 0.0 THEN
      rtn := 0.0;
    END IF;
    RETURN rtn;
  END
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.fractionDone() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.fractionDone( theStn bigint) returns float as $$
  DECLARE
    rtn float;
    cp record;
  BEGIN
    SELECT extract( epoch from (now() - cpts))/(0.1+abs(extract( epoch from (cpdonetime-cpts)))) INTO rtn FROM cats.curpath WHERE cpstn=theStn ORDER BY cpkey desc LIMIT 1;
    IF NOT FOUND OR rtn > 1.0 THEN
      rtn := 1.0;
    END IF;
    IF rtn < 0.0 THEN
      rtn := 0.0;
    END IF;
    RETURN rtn;
  END
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.fractionDone( bigint) OWNER TO lsadmin;

-------------
CREATE OR REPLACE FUNCTION cats.put( theId int, x int, y int, z int) returns int AS $$
  SELECT cats._mkcryocmd( 'put', $1, 0, $2, $3, $4);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.put( int, int, int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.put( theId int, x int, y int, z int, esttime numeric) returns int AS $$
  SELECT cats._mkcryocmd( 'put', $1, 0, $2, $3, $4, $5);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.put( int, int, int, int, numeric) OWNER TO lsadmin;
------------
CREATE OR REPLACE FUNCTION cats.put_bcrd( theId int, x int, y int, z int) returns int AS $$
  SELECT cats._mkcryocmd( 'put_bcrd', $1, 0, $2, $3, $4);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.put_bcrd( int, int, int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.put_bcrd( theId int, x int, y int, z int, esttime numeric) returns int AS $$
  SELECT cats._mkcryocmd( 'put_bcrd', $1, 0, $2, $3, $4, $5);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.put_bcrd( int, int, int, int, numeric) OWNER TO lsadmin;

-------------

CREATE OR REPLACE FUNCTION cats.get( x int, y int, z int) returns int AS $$
  SELECT cats._mkcryocmd( 'get', 0, 0, $1, $2, $3);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.get( int, int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.get( x int, y int, z int, esttime numeric) returns int AS $$
  SELECT cats._mkcryocmd( 'get', 0, 0, $1, $2, $3, $4);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.get( int, int, int) OWNER TO lsadmin;


----------

CREATE OR REPLACE FUNCTION cats.getput( theId int, xx int, yy int, zz int) returns int AS $$
  SELECT cats.getput( $1, $2, $3, $4, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.getput( int, int, int, int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.getput( theId int, xx int, yy int, zz int, esttime numeric) returns int AS $$
  DECLARE
    rtn int;
    tool1 int;
    tool2 int;
  BEGIN
    SELECT cttoolno INTO tool1 FROM cats._cylinder2tool WHERE ctcyl = (px.getCurrentSampleID() & x'0000ff00'::int) >> 8;
    SELECT cttoolno INTO tool2 FROM cats._cylinder2tool WHERE ctcyl = (theId                   & x'0000ff00'::int) >> 8;

    IF tool1 != tool2 THEN
      PERFORM cats.get( xx, yy, zz, esttime);
      SELECT cats.put( theId, xx, yy, zz, esttime) INTO rtn;
    ELSE
      SELECT cats._mkcryocmd( 'getput', theId, 0, xx, yy, zz, esttime) INTO rtn;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getput( int, int, int, int, numeric) OWNER TO lsadmin;


--------

CREATE OR REPLACE FUNCTION cats.getput_bcrd( theId int, x int, y int, z int) returns int AS $$
  SELECT cats._mkcryocmd( 'getput_bcrd', $1, 0, $2, $3, $4);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.getput_bcrd( int, int, int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.getput_bcrd( theId int, xx int, yy int, zz int, esttime numeric) returns int AS $$
  DECLARE
    rtn int;
    tool1 int;
    tool2 int;
  BEGIN
    SELECT cttoolno INTO tool1 FROM cats._cylinder2tool WHERE ctcyl = (px.getCurrentSampleID() & x'0000ff00'::int) >> 8;
    SELECT cttoolno INTO tool2 FROM cats._cylinder2tool WHERE ctcyl = (theId                   & x'0000ff00'::int) >> 8;

    IF tool1 != tool2 THEN
      PERFORM cats.get( xx, yy, zz, esttime);
      SELECT cats.put_bcrd( theId, xx, yy, zz, esttime) INTO rtn;
    ELSE
      SELECT cats._mkcryocmd( 'getput_bcrd', theId, 0, xx, yy, zz, esttime) INTO rtn;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.getput( int, int, int, int, numeric) OWNER TO lsadmin;

--------

CREATE OR REPLACE FUNCTION cats.barcode( theId int) returns int AS $$
  SELECT cats._mkcryocmd( 'barcode', $1, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.barcode( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.transfer( theId int, theNewId int) returns int AS $$
  SELECT cats._mkcryocmd( 'transfer', $1, $2, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.transfer( int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.soak( theId int) returns int AS $$
  SELECT cats._mkcryocmd( 'soak', $1, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.soak( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.dry( theId int) returns int AS $$
  SELECT cats._mkcryocmd( 'dry', $1, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.dry( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.home( theId int) returns int AS $$
  SELECT cats._mkcryocmd( 'home', $1, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.home( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.back( theId int) returns int AS $$
  SELECT cats._mkcryocmd( 'back', $1, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.back( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.safe( theId int) returns int AS $$
  SELECT cats._mkcryocmd( 'safe', $1, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.safe( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.reference( ) returns int AS $$
  SELECT cats._mkcryocmd( 'reference', 0, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.reference( ) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.openlid1() returns void AS $$
  SELECT cats._pushqueue( 'openlid1');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.openlid1() OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.openlid2() returns void AS $$
  SELECT cats._pushqueue( 'openlid2');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.openlid2() OWNER TO lsadmin;
  

CREATE OR REPLACE FUNCTION cats.openlid3() returns void AS $$
  SELECT cats._pushqueue( 'openlid3');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.openlid3() OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.closelid1() returns void AS $$
  SELECT cats._pushqueue( 'closelid1');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closelid1() OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.closelid2() returns void AS $$
  SELECT cats._pushqueue( 'closelid2');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closelid2() OWNER TO lsadmin;
  

CREATE OR REPLACE FUNCTION cats.closelid3() returns void AS $$
  SELECT cats._pushqueue( 'closelid3');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closelid3() OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.opentool() returns void AS $$
  SELECT cats._pushqueue( 'opentool');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.opentool() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.closetool() returns void AS $$
  SELECT cats._pushqueue( 'closetool');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closetool() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.magneton() returns void AS $$
  SELECT cats._pushqueue( 'magneton');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.magneton() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.magnetoff() returns void AS $$
  SELECT cats._pushqueue( 'magnetoff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.magnetoff() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.heateron() returns void AS $$
  SELECT cats._pushqueue( 'heateron');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.heateron() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.heateroff() returns void AS $$
  SELECT cats._pushqueue( 'heateroff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.heateroff() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.regulon() returns void AS $$
  SELECT cats._pushqueue( 'regulon');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.regulon() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.reguloff() returns void AS $$
  SELECT cats._pushqueue( 'reguloff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.reguloff() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.warmon() returns void AS $$
  SELECT cats._pushqueue( 'warmon');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.warmon() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.warmoff() returns void AS $$
  SELECT cats._pushqueue( 'warmoff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.warmoff() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.on() returns void AS $$
  SELECT cats._pushqueue( 'on');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.on() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.off() returns void AS $$
  SELECT cats._pushqueue( 'off');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.off() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.abort() returns void AS $$
  SELECT cats._pushqueue( 'abort');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.abort() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.reset() returns void AS $$
  SELECT cats._pushqueue( 'reset');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.reset() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.panic() returns void AS $$
  SELECT cats._pushqueue( 'panic');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.panic() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.pause() returns void AS $$
  SELECT cats._pushqueue( 'pause');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.pause() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.restart() returns void AS $$
  SELECT cats._pushqueue( 'restart');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.restart() OWNER TO lsadmin;


-------------------------
--
-- Explicit station
--
-------------------------

CREATE OR REPLACE FUNCTION cats.barcode( theStn bigint, theId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'barcode', $2, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.barcode( bigint, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.transfer( theStn bigint, theId int, theNewId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'transfer', $2, $3, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.transfer( bigint, int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.soak( theStn bigint, theId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'soak', $2, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.soak( bigint, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.dry( theStn bigint, theId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'dry', $2, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.dry( bigint, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.home( theStn bigint, theId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'home', $2, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.home( bigint, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.back( theStn bigint, theId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'back', $2, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.back( bigint, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.safe( theStn bigint, theId int) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'safe', $2, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.safe( bigint, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.reference( theStn bigint) returns int AS $$
  SELECT cats._mkcryocmd( $1, 'reference', 0, 0, 0, 0, 0);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION cats.reference( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.openlid1( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'openlid1');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.openlid1( bigint) OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.openlid2( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'openlid2');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.openlid2( bigint) OWNER TO lsadmin;
  

CREATE OR REPLACE FUNCTION cats.openlid3( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'openlid3');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.openlid3( bigint) OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.closelid1( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'closelid1');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closelid1( bigint) OWNER TO lsadmin;
  
CREATE OR REPLACE FUNCTION cats.closelid2( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'closelid2');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closelid2( bigint) OWNER TO lsadmin;
  

CREATE OR REPLACE FUNCTION cats.closelid3( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'closelid3');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closelid3( bigint) OWNER TO lsadmin;

---



CREATE OR REPLACE FUNCTION cats.opentool( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'opentool');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.opentool( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.closetool( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'closetool');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.closetool( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.magneton( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'magneton');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.magneton( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.magnetoff( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'magnetoff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.magnetoff( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.heateron( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'heateron');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.heateron( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.heateroff( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'heateroff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.heateroff( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.regulon( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'regulon1');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.regulon( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.reguloff( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'reguloff1');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.reguloff( bigint) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.warmon( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'warmon');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.warmon( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.warmoff( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'warmoff');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.warmoff( bigint) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.on( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'on');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.on( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.off( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'off');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.off( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.abort( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'abort');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.abort( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.reset( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'reset');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.reset( bigint) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION cats.panic( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'panic');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.panic( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.pause( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'pause');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.pause( bigint) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.restart( theStn bigint) returns void AS $$
  SELECT cats._pushqueue( $1, 'restart');
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION cats.restart( bigint) OWNER TO lsadmin;


------------------------------------------------

CREATE TABLE cats.magnetstates (
       msKey serial primary key,
       msTS timestamp with time zone default now(),
       msStn bigint references px.stations (stnkey),
       msSamplePresent boolean not null
);
ALTER TABLE cats.magnetstates OWNER to lsadmin;


CREATE OR REPLACE FUNCTION cats.recover_SPINE_dismount_failure() returns boolean AS $$
  DECLARE
    rtn boolean;
    ta  record;		-- transfer arguments
  BEGIN
    rtn := True;
    PERFORM cats.abort();
    PERFORM cats.reset();
    PERFORM cats.safe(0);
    PERFORM cats.back(0);
    SELECT * INTO ta FROM px.transferArgs WHERE taStn=px.getstation() ORDER BY taKey DESC LIMIT 1;
    PERFORM px.startTransfer( ta.cursam, False, ta.taxx, ta.tayy, ta.tazz);
    PERFORM px.startTransfer( ta.taId, False, ta.taxx, ta.tayy, ta.tazz);

    return rtn;
  END;
$$ LANGUAGE PLPGSQL SECURITY DEFINER;
ALTER FUNCTION cats.recover_SPINE_dismount_failure() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.recover_dismount_failure() returns boolean AS $$
  DECLARE
   rtn boolean;
   tn int;   -- current tool number
  BEGIN
    rtn := FALSE;
    SELECT cttoolno INTO tn FROM cats._cylinder2tool LEFT JOIN cats.states ON csToolNumber=cttoolname OR csToolNumber=cttoolname WHERE csStn=px.getstation() ORDER BY cskey DESC LIMIT 1;
    IF FOUND THEN
      IF tn = 2 THEN -- The SPINE/EMBL tool
        SELECT cats.recover_SPINE_dismount_failure() INTO rtn;
      END IF;
    END IF;
    return rtn;
  END;
$$ LANGUAGE PLPGSQL SECURITY DEFINER;
ALTER FUNCTION cats.recover_dismount_failure() OWNER TO lsadmin;


CREATE TABLE cats._cmdTiming (
       ctkey serial primary key,
       ctstn bigint references px.stations (stnkey),
       ctpath text NOT NULL,
       ctool int  NOT NULL,
       ctstart timestamp with time zone default now(),		-- time command was sent to robot
       ctneedair timestamp with time zone default null,		-- time we needed air rights
       ctgotair  timestamp with time zone default null,		-- time we got air rights
       ctnoair   timestamp with time zone default null,		-- time we no longer needed air rights
       ctdone    timestamp with time zone default null		-- time we became done
);
ALTER TABLE cats._cmdTiming OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.cmdTimingStart( thePath text, theTool int) returns void as $$
  DECLARE
  BEGIN
    DELETE FROM cats._cmdTiming WHERE ctpath=thePath and ctool=theTool and ctdone is null;
    INSERT INTO	cats._cmdTiming (ctstn, ctpath, ctool) values (px.getstation(), thePath, theTool);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.cmdTimingStart( text, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.cmdTimingNeedAir() returns void as $$
  DECLARE
  BEGIN
    UPDATE cats._cmdTiming SET ctneedair=now() WHERE ctkey = (SELECT ctkey FROM cats._cmdTiming WHERE ctstn=px.getStation() ORDER BY ctkey desc LIMIT 1);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.cmdTimingNeedAir() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.cmdTimingGotAir() returns void as $$
  DECLARE
  BEGIN
    UPDATE cats._cmdTiming SET ctgotair=now() WHERE ctkey = (SELECT ctkey FROM cats._cmdTiming WHERE ctstn=px.getStation() ORDER BY ctkey desc LIMIT 1);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.cmdTimingGotAir() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.cmdTimingNoAir() returns void as $$
  DECLARE
  BEGIN
    UPDATE cats._cmdTiming SET ctnoair=now() WHERE ctkey = (SELECT ctkey FROM cats._cmdTiming WHERE ctstn=px.getStation() ORDER BY ctkey desc LIMIT 1);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.cmdTimingNoAir() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.cmdTimingDone() returns void as $$
  DECLARE
    donetime interval;
    airtime  interval;
    noairtime interval;
    thePath text;
    theTool int;
    theKey  bigInt;
  BEGIN
    SELECT ctkey, ctool, ctpath INTO theKey, theTool, thePath FROM cats._cmdTiming WHERE ctstn=px.getStation() and ctdone is null ORDER BY ctkey desc LIMIT 1;
    IF NOT FOUND or theTool is null or thePath is null THEN
      return;
    END IF;
    UPDATE cats._cmdTiming SET ctdone=now() WHERE ctkey = theKey;

    SELECT avg(ctneedair-ctstart), avg(ctnoair-ctstart), avg(ctdone-ctstart) INTO airtime, noairtime, donetime
        FROM cats._cmdTiming
        WHERE ctkey IN (SELECT ctkey
                               FROM cats._cmdTiming
                               WHERE ctstn=px.getStation()
                                 and ctool=theTool
                                 and ctpath=thePath
                                 and ctdone is not null
                               ORDER BY ctkey DESC
                               LIMIT 10);

    IF airtime is not null and noairtime is not null and donetime is not null THEN
      PERFORM 1 FROM cats._tooltiming WHERE tttool=theTool and ttpath=thePath and ttstn=px.getStation();
      IF FOUND THEN
        --
        -- Don't change the timing if it'll change by more than 20 percent
        -- When a major path change takes place simply delete the tooltiming entry and 
        -- let the statistics start anew.
        --
        UPDATE cats._tooltiming SET ttair=airtime, ttnoair=noairtime, ttdone=donetime
               WHERE tttool=theTool
                 and ttpath=thePath
                 and abs( extract( epoch from (ttair-airtime)))     < 0.2 * extract( epoch from ttair)
                 and abs( extract( epoch from (ttnoair-noairtime))) < 0.2 * extract( epoch from ttnoair)
                 and abs( extract( epoch from (ttdone-donetime)))   < 0.2 * extract( epoch from ttdone)
                 and ttstn=px.getStation();
      ELSE
        INSERT INTO cats._tooltiming (ttair, ttnoair, ttdone, ttstn, tttool, ttpath) VALUES (airtime, noairtime, donetime, px.getStation(), theTool, thePath);
      END IF;
    END IF;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.cmdTimingDone() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION cats.cmdTimingAbort() returns void as $$
  DECLARE
  BEGIN
    DELETE FROM cats._cmdTiming WHERE ctstn=px.station() and ctdone is null;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.cmdTimingAbort() OWNER TO lsadmin;


CREATE TYPE cats.machineStateType as ( "Station" int, "State" int);

CREATE OR REPLACE FUNCTION cats.machineState() returns setof cats.machineStateType AS $$
  --
  -- Must be owned by a privileged user
  DECLARE
    rtn cats.machineStateType;
    tExcl int;
    tSamp int;
    tPath int;
    tDAR  int;
    tmp   int;
    cid   int;
  BEGIN
    

    FOR cid,tPath,tDAR,tmp IN SELECT  classid,
          (bool_or(coalesce(length(cspathname),0)>0))::int * 128,
          (bool_or(coalesce(cdiffractometer=client_addr and objid=2,false)))::int * 64,
          bit_or((2^(objid::int-1))::int)
        FROM pg_locks
        LEFT JOIN pg_stat_activity ON procpid=pid
        LEFT JOIN px._config ON cstnkey=classid
        LEFT JOIN cats.states on classid=csstn
        WHERE locktype='advisory' and objid < 32 and granted and classid < 5 and classid > 0
        GROUP BY classid
        ORDER BY classid
      LOOP
      rtn."Station" = cid;
      SELECT CASE WHEN cats.tooclose(cid) THEN 512 ELSE 0 END INTO tExcl;

      SELECT CASE WHEN px.getcurrentsampleid(cid)=px.lastsample(cid) THEN 256 ELSE 0 END INTO tSamp;

      rtn."State"   = tmp + tExcl + tSamp + tDAR + tPath;
      return next rtn;
    END LOOP;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.machineState() OWNER TO brister;

CREATE OR REPLACE FUNCTION cats.machineState( theStn bigint) returns int AS $$
  --
  -- Must be owned by a privileged user
  DECLARE
    rtn   int;
    tExcl int;
    tSamp int;
    tPath int;
    tDAR  int;
    tmp   int;
  BEGIN
    

   SELECT INTO tPath, tDAR, tmp
        (bool_or(coalesce(length(cspathname),0)>0))::int * 128,
        (bool_or(coalesce(cdiffractometer=client_addr and objid=2,false)))::int * 64,
        bit_or((2^(objid::int-1))::int)
      FROM pg_locks
      LEFT JOIN pg_stat_activity ON procpid=pid
      LEFT JOIN px._config ON cstnkey=theStn
      LEFT JOIN cats.states on csstn=theStn
      WHERE locktype='advisory' and objid < 32 and granted;

    SELECT CASE WHEN cats.tooclose(theStn) THEN 512 ELSE 0 END INTO tExcl;

    SELECT CASE WHEN px.getcurrentsampleid(theStn)=px.lastsample(theStn) THEN 256 ELSE 0 END INTO tSamp;

    rtn = tmp + tExcl + tSamp + tDAR + tPath;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION cats.machineState( bigint) OWNER TO brister;
