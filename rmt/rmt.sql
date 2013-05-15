--
-- Support for data collection at LS-CAT
--
-- Copyright 2008-2013 by Keith Brister, Northwestern University
--
--   This file is part of the LS-CAT Beamline Control Package which is
--   free software: you can redistribute it and/or modify it under the
--   terms of the GNU General Public License as published by the Free
--   Software Foundation, either version 3 of the License, or (at your
--   option) any later version.
--
--   This software is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
--   General Public License for more details.
--
--   You should have received a copy of the GNU General Public License
--   along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
--
--
-- Support for px data collection
--
--

BEGIN;
DROP SCHEMA rmt CASCADE;
CREATE SCHEMA rmt;
GRANT USAGE ON SCHEMA rmt TO lsuser;
GRANT USAGE ON SCHEMA rmt TO lsadmin;

CREATE TABLE rmt.roles (
       --
       -- The various roles allowed
       --
       rName text primary key
);
ALTER TABLE rmt.roles OWNER TO lsadmin;

INSERT INTO rmt.roles (rName) values ('None');
--INSERT INTO rmt.roles (rName) values ('Buyer');
--INSERT INTO rmt.roles (rName) values ('Seller');
--INSERT INTO rmt.roles (rName) values ('Auctioneer');
--INSERT INTO rmt.roles (rName) values ('Administrator');
INSERT INTO rmt.roles (rName) values ('RemoteUser');
INSERT INTO rmt.roles (rName) values ('MailInUser');
INSERT INTO rmt.roles (rName) values ('Staff');

CREATE OR REPLACE FUNCTION rmt.getrolenames() returns setof text as $$
  SELECT rname FROM rmt.roles ORDER BY rname;
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION rmt.getrolenames() OWNER TO lsadmin;


CREATE TABLE rmt.rolePages (
       --
       -- the xsl web page generators allowed
       --
       rpKey serial primary key,        -- our key
       rpRole text                      -- the role this page is for
              references rmt.roles (rName),
       rpName text not null,            -- what we call it
       rpFile text not null,            -- where it is
       unique( rpRole, rpName)          -- each role is allowed only one entry of a given page name
);
ALTER TABLE rmt.rolePages OWNER TO lsadmin;

INSERT INTO rmt.rolePages (rpRole, rpName, rpFile) values ( 'None',          'index', 'xsl/noneHome.xsl');
INSERT INTO rmt.rolePages (rpRole, rpName, rpFile) values ( 'RemoteUser',    'index', 'xsl/remoteUserHome.xsl');
INSERT INTO rmt.rolePages (rpRole, rpName, rpFile) values ( 'MailInUser',    'index', 'xsl/mailInUserHome.xsl');
INSERT INTO rmt.rolePages (rpRole, rpName, rpFile) values ( 'Staff',         'index', 'xsl/staffHome.xsl');


CREATE OR REPLACE FUNCTION rmt.getrolepages( theRole text) returns setof rmt.rolepages as $$
  SELECT * FROM rmt.rolePages WHERE rpRole=$1 ORDER BY rpName;
$$ LANGUAGE SQL SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getrolepages( text) OWNER TO lsadmin;


CREATE TABLE rmt.pids (
-- tracks session pids
       pKey serial primary key,                                 -- our primary key
       pCreateTs timestamp with time zone default now(),        -- creation time stamp
       pUsedTs   timestamp with time zone default now(),        -- time last accessed
       pActive   boolean not null default false,                -- Are we active?
       pPid      text not null unique,                          -- the PID itself
       pUid      text not null,                                 -- LDAP Authenticated UID
       pBdg      int not null,                                  -- APS Badge Number
       pRole     text not null                                  -- The role
                 references rmt.roles (rname)
);
ALTER TABLE rmt.pids OWNER TO lsadmin;
GRANT SELECT ON rmt.pids TO lsuser;

CREATE OR REPLACE FUNCTION rmt.pidInsertTF1() returns trigger as $$
--
-- We don't let anyone else enter a PID: We don't want some client program to
-- insert a bogus PID and cause problems.  This function ignores what ever PID
-- was specified
--
  BEGIN
    new.ppid=md5(now()::text||random()::text);
    return new;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.pidInsertTF1() OWNER TO lsadmin;

CREATE TRIGGER pidInsertTrigger1 BEFORE INSERT ON rmt.pids FOR EACH ROW EXECUTE PROCEDURE rmt.pidInsertTF1();


CREATE OR REPLACE FUNCTION rmt.pidInsertOrUpdateTF2() returns trigger as $$
--
-- reject any attempt to insert or update an entry to an unallowed user/role/account combo
  BEGIN
    IF NEW.pRole = 'None' or NEW.pRole = 'RemoteUser' or NEW.pRole = 'MailInUser' THEN
      return NEW;
    END IF;

    IF NEW.pRole = 'Robo' and NEW.pUid='robo' THEN
      return NEW;
    END IF;

    PERFORM 1 FROM rmt.allowedRoles WHERE arUID=NEW.pUid and arRole=NEW.pRole;
    IF NOT FOUND THEN
      return NULL;
    END IF;
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.pidInsertOrUpdateTF2() OWNER TO lsadmin;

CREATE TRIGGER pidInsertOrUpdateTrigger2 BEFORE INSERT OR UPDATE ON rmt.pids FOR EACH ROW EXECUTE PROCEDURE rmt.pidInsertOrUpdateTF2();


CREATE OR REPLACE FUNCTION rmt.pidUpdateTF1() returns trigger as $$
  --
  -- Aborts the update if someone tries to change the pid
  --
  BEGIN
    IF NEW.pPid != OLD.pPid THEN
      return NULL;
    END IF;
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.pidUpdateTF1() OWNER TO lsadmin;

CREATE TRIGGER pidUpdateTrigger BEFORE UPDATE ON rmt.pids FOR EACH ROW EXECUTE PROCEDURE rmt.pidUpdateTF1();

CREATE OR REPLACE FUNCTION rmt.checkPassword( theuid text, thepwd text) returns int as $$
    if not GD.has_key( "ldap"):
        import ldap
        GD["ldap"] = ldap
    ldap = GD["ldap"]
        
    l=ldap.initialize( "ldap://contrabass.ls-cat.org")
    eptl = l.search_s("dc=people,dc=ls-cat,dc=org", ldap.SCOPE_SUBTREE, "(uid=%s)" % (str(theuid)), ["apsBadgeNo"])
    if len(eptl) != 1:
        return 0
    bn = eptl[0][1]["apsBadgeNo"][0]

    try:
        l.bind_s( 'cn=%s,dc=people,dc=ls-cat,dc=org' % (bn), thepwd)
    except ldap.INVALID_CREDENTIALS:
        return 0
    except:
        return 0

    l.unbind_s()
    return bn
$$ LANGUAGE plpythonu SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.checkPassword( text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getHomeDirectory( theesaf int) returns text as $$
    if not GD.has_key( "ldap"):
        import ldap
        GD["ldap"] = ldap
    ldap = GD["ldap"]
        
    l=ldap.initialize( "ldap://contrabass.ls-cat.org")
    eptl = l.search_s("dc=esaf,dc=ls-cat,dc=org", ldap.SCOPE_SUBTREE, "(esafExpid=%d)" % (int(theesaf)), ["homeDirectory"])
    if len(eptl) != 1:
        return ''
    hd = eptl[0][1]["homeDirectory"][0]

    return hd
$$ LANGUAGE plpythonu SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getHomeDirectory( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getBuDirectory( theesaf int) returns text as $$
    if not GD.has_key( "ldap"):
        import ldap
        GD["ldap"] = ldap
    ldap = GD["ldap"]
        
    l=ldap.initialize( "ldap://contrabass.ls-cat.org")
    eptl = l.search_s("dc=esaf,dc=ls-cat,dc=org", ldap.SCOPE_SUBTREE, "(esafExpid=%d)" % (int(theesaf)), ["buDirectory"])
    if len(eptl) != 1:
        return ''
    hd = eptl[0][1]["buDirectory"][0]

    return hd
$$ LANGUAGE plpythonu SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getBuDirectory( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getUID( theesaf int) returns text as $$
    if not GD.has_key( "ldap"):
        import ldap
        GD["ldap"] = ldap
    ldap = GD["ldap"]
        
    l=ldap.initialize( "ldap://contrabass.ls-cat.org")
    eptl = l.search_s("dc=esaf,dc=ls-cat,dc=org", ldap.SCOPE_SUBTREE, "(esafExpid=%d)" % (int(theesaf)), ["uidNumber"])
    if len(eptl) != 1:
        return ''
    uid = eptl[0][1]["uidNumber"][0]

    return uid
$$ LANGUAGE plpythonu SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getUid( int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getGid( theesaf int) returns text as $$
    if not GD.has_key( "ldap"):
        import ldap
        GD["ldap"] = ldap
    ldap = GD["ldap"]
        
    l=ldap.initialize( "ldap://contrabass.ls-cat.org")
    eptl = l.search_s("dc=esaf,dc=ls-cat,dc=org", ldap.SCOPE_SUBTREE, "(esafExpid=%d)" % (int(theesaf)), ["gidNumber"])
    if len(eptl) != 1:
        return ''
    gid = eptl[0][1]["gidNumber"][0]

    return gid
$$ LANGUAGE plpythonu SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getGid( int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.getPid( u text, p text) returns text as $$
--
-- u is the uid and p is the password
-- If these match up then we generate a new PID and let
-- the user access the database without much further fuss
--
  DECLARE
    badgeno int;        -- log in OK
    theRole   text;     -- our role to play
    theUid    text;     -- a "corrected" version of the user name u
    rtn text;           -- the return value
  BEGIN
    theUid := regexp_replace(lower( trim(u)), '[^a-z0-9]', '', 'g');
    IF length( theUid) <= 0 THEN
      return NULL;
    END IF;

    --
    -- look up role and account from the user name and password
    -- if the defaults for the user are not also in the userAccnts table then the
    -- login is not allowed
    --
    
    SELECT rmt.checkPassword( theUid, p) INTO badgeno;
    IF NOT FOUND OR badgeno = 0 THEN
      return NULL;
    END IF;

    theRole := 'RemoteUser';
    PERFORM 1 FROM rmt.allowedroles WHERE aruid=theUid and arrole='Staff';
    IF FOUND THEN
      theRole = 'Staff';
    END IF;
      

    INSERT INTO rmt.pids (pBdg, pUid, pRole, pActive) VALUES (badgeno, theUid, theRole, True);
    --
    -- The pid is generated by the insert trigger function
    --
    SELECT pPid INTO rtn FROM rmt.pids WHERE pKey=currval( 'rmt.pids_pkey_seq');
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.getPid( text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getrobopid( esaf int) returns text as $$
  --
  -- rmt.getrobopid
  --
  -- get a valid pid for robotic processes
  --
  DECLARE
    rtn text;
    bdgno int;

  BEGIN
    PERFORM 1 FROM px.logins WHERE lesaf=esaf and louts is null;
    IF NOT FOUND THEN
      return NULL;
    END IF;

    SELECT INTO bdgno expbadgeno FROM esaf.experimenter WHERE expspokesperson='Y' and expexperimentid=esaf LIMIT 1;

    IF NOT FOUND THEN
      return NULL;
    END IF;

    SELECT INTO rtn ppid FROM rmt.pids WHERE pBdg = bdgno and pUid = 'robo' and pRole = 'Robo' and pActive;
    IF NOT FOUND THEN
      INSERT INTO rmt.pids (pBdg, pUid, pRole, pActive) VALUES ( bdgno, 'robo', 'Robo', True);
      SELECT pPid INTO rtn FROM rmt.pids WHERE pKey=currval( 'rmt.pids_pkey_seq');
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.getrobopid( int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.getU( pid text) returns text as $$
  DECLARE
    rtn text;
  BEGIN
    SELECT pUid INTO rtn FROM rmt.pids WHERE pPid=pid;
    IF NOT FOUND THEN
      RETURN NULL;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER IMMUTABLE;
ALTER FUNCTION rmt.getU( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.logout( pid text) returns text as $$
  DELETE FROM rmt.uistreams WHERE uispid=$1;
  UPDATE rmt.pids SET pActive=False WHERE pPid=$1;
  SELECT rmt.getU( $1);
$$ LANGUAGE sql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.logout( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.checkPid( a text) returns boolean as $$
--
-- Returns true if pid is legal
-- and updates pUsedTs
-- And you're right, the timeout should not be hardwired here.
--
  BEGIN
    --
    -- Double check that the user is still allowed to access this account and use this role
    --
    PERFORM 1
      FROM rmt.pids
      WHERE a=pPid and pActive and pUsedTs+'1 hours' > now();
    IF FOUND THEN
      UPDATE rmt.pids SET pUsedTs=now() WHERE pPid=a;
      return TRUE;
    END IF;
    DELETE FROM rmt.uistreams WHERE uispid=a;
    UPDATE rmt.pids SET pActive=false WHERE pPid=a;
    return FALSE;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.checkPid( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.checkPidPassive( thepid text) RETURNS boolean AS $$
  --
  -- check that the pid is valid
  -- Use this call when the request is part of an automated process
  --
  BEGIN
    PERFORM 1 FROM rmt.pids WHERE pPid=thepid and pActive and pUsedTs+'1 hours' > now();
    IF FOUND THEN
      return TRUE;
    END IF;
    DELETE FROM rmt.uistreams WHERE uispid=thepid;
    UPDATE rmt.pids SET pActive=false WHERE pPid=thepid;
    return FALSE;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.checkPidPassive( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.checkRole( pid text, theRole text) returns boolean as $$
  --
  -- Returns true if the pid is valid and has the role specified by theRole
  -- Returns False otherwise
  --
  DECLARE
    tf boolean;
  BEGIN
    SELECT pRole=theRole INTO tf FROM rmt.pids WHERE rmt.checkPid( pid) and pPid=pid;
    IF NOT FOUND OR tf=False THEN
      return False;
    END IF;
    return True;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.checkRole( pid text, theRole text) OWNER TO lsadmin;




CREATE TABLE rmt.allowedRoles (
  arKey serial primary key,
  arUID text not null,
  arRole text not null references rmt.roles (rname),
  UNIQUE (arUID, arRole)
);
ALTER TABLE rmt.allowedRoles OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.newrole( pid text, newrole text) returns boolean AS $$
  --
  -- sets the user's role and returns true or, if the new role is
  --  not allowed for this user, returns false
  --
  DECLARE
  BEGIN
    PERFORM 1 FROM rmt.pids
              LEFT JOIN rmt.allowedRoles ON pUid=arUID
              WHERE  arRole=newrole;

    IF NOT FOUND THEN
      return False;
    END IF;
    UPDATE rmt.pids SET pRole=newrole WHERE pPid=pid;
    return True;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.newrole( text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getrole( pid text) returns text AS $$
  --
  -- returns the current role the user has
  --
    SELECT pRole FROM rmt.pids WHERE pPid=$1;
$$ LANGUAGE sql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.getrole( text) OWNER TO lsadmin;


--
--=================================================
--=================================================
--
-- Track user input via these tables
-- This allows a simpler editing interface
--
--=================================================
--=================================================

CREATE TABLE rmt.editVars (
       evKey serial primary key,        -- our key
       evName text not null unique,     -- the variable name as it appears in forms
       evDefault text default '',       -- the Default Value, if any
       evValid   text default NULL      -- a bit of SQL to check validate input
);
ALTER TABLE rmt.editVars OWNER TO lsadmin;

CREATE TABLE rmt.evACLPermissions (
       -- allowed actions for a given variable
       pName text primary key
);

INSERT INTO rmt.evACLPermissions (pName) values ('ReadOnly');
INSERT INTO rmt.evACLPermissions (pName) values ('ReadWrite');

CREATE TABLE rmt.evACL (
       -- Access control list for the live variables
       -- This allows us to specify which variables are allowed to be set
       -- for each role.
       aclKey serial primary key,       -- our key
       aclVar text                      -- name of the variable (ev or lv)
              references rmt.editVars (evname) on update cascade,
       aclRole text                     -- role allowed to set this variable
              references rmt.roles (rName) on update cascade,
       aclPerm text                     -- what this role is allowed to do with this variable
              references rmt.evACLPermissions (pName) on update cascade
);
ALTER TABLE rmt.evACL OWNER TO lsadmin;

CREATE TABLE rmt.liveVars (
       lvKey serial primary key,                        -- our key
       lvTs  timestamp with time zone default now(),    -- we don't change the value, only insert a new entry, if needed, and update the timestamp
       lvPid text not null                              -- the editing process
                    references rmt.pids (pPid),
       lvVar text not null                              -- the variable we are dealing with
                    references rmt.editVars (evName),
       lvVal text not null default ''                   -- its value
);
ALTER TABLE rmt.liveVars OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.liveVarsInsertTF() returns trigger as $$
  --
  -- Here we check that the editVar name exists and cancel the insert if it's not found.
  -- The constrants on the live var table will also prevent this from happening
  -- but here we can do so without throwing an exception
  --
  DECLARE
  BEGIN
    PERFORM 1 FROM rmt.editVars WHERE evName=NEW.lvvar;
    IF NOT FOUND THEN
      return NULL;
    END IF;
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.liveVarsInsertTF() OWNER TO lsadmin;

CREATE TRIGGER lvInsertTF1 BEFORE INSERT ON rmt.liveVars FOR EACH ROW EXECUTE PROCEDURE rmt.liveVarsInsertTF();


CREATE TYPE rmt.liveVarType AS ( pid text, var text, val text);
ALTER TYPE rmt.liveVarType OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getLiveVars( p text) returns setof rmt.liveVarType as $$
  --
  -- Get all the variables
  -- Here we check the permissions to be sure only the allowed variables are returned
  -- in case the user changed roles somehow
  --
  SELECT $1, lvvar, lvval
    FROM rmt.livevars
    LEFT JOIN rmt.pids on pPid=$1
    LEFT JOIN rmt.evACL on aclVar=lvvar and aclRole=pRole
    WHERE lvpid=$1 and
      (aclPerm = 'ReadOnly' or aclPerm = 'ReadWrite') and
      ROW( lvts,lvvar) IN (SELECT max(lvts), lvvar FROM rmt.livevars WHERE lvpid=$1 GROUP BY lvvar);
$$ LANGUAGE SQL VOLATILE;
ALTER FUNCTION rmt.getLiveVars( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.getLiveVarListRW( p text) returns setof text as $$
  SELECT evname FROM rmt.editvars LEFT JOIN rmt.evacl ON aclvar=evname WHERE aclperm='ReadWrite' and aclrole=rmt.getrole( $1);
$$ LANGUAGE sql SECURITY DEFINER;
ALTER FUNCTION rmt.getLiveVarListRW( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getLiveVar( p text, var text) returns text as $$
  SELECT val FROM rmt.getLiveVars($1) WHERE var=$2
$$ LANGUAGE SQL VOLATILE;
ALTER FUNCTION rmt.getLiveVar( pid text, var text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.getSubbieLiveVar( pid text) returns text as $$
  DECLARE
    rtn text;
    ts  timestamptz;
  BEGIN
    SELECT max(lvTs) INTO ts FROM rmt.liveVars WHERE lvPid=pid;
    IF NOT FOUND THEN
      return NULL;
    END IF;
    SELECT val INTO rtn FROM rmt.getLiveVars(pid) WHERE var LIKE 'subbie%' and lvTs=ts LIMIT 1;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getSubbieLiveVar( pid text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.setLiveVars( p text, var text, val text) returns int AS $$
  DECLARE
  BEGIN
    --
    -- Check that the user's current role is allowed to set this variable
    --
    PERFORM 1
      FROM rmt.pids
      LEFT JOIN rmt.evACL on aclVar=var and aclRole=pRole
      WHERE aclPerm='ReadWrite' and aclVar=var and aclRole=pRole and pPid=p;
    IF NOT FOUND THEN
      return 0;
    END IF;

    INSERT INTO rmt.livevars (lvpid, lvvar, lvval) VALUES ( p, var, val);
    return 1;
  END;

$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.setLiveVars( pid text, var text, val text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.pidInsertTF2() returns trigger as $$
--
-- This trigger function sets up the editing variables we'll be needing whenever a new PID is requested
--
  DECLARE
   v record;
  BEGIN
    FOR v IN SELECT *
        FROM rmt.editVars
        LEFT JOIN rmt.evACL on evName=aclVar
        WHERE aclRole=NEW.pRole and aclPerm='ReadWrite'
      LOOP

      INSERT INTO rmt.liveVars (lvPid, lvVar, lvVal) VALUES (NEW.pPid, v.evName, v.evDefault);
    END LOOP;

    return NULL;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.pidInsertTF2() OWNER TO lsadmin;


CREATE TRIGGER pidInsertTrigger2 AFTER INSERT ON rmt.pids FOR EACH ROW EXECUTE PROCEDURE rmt.pidInsertTF2();

CREATE TABLE rmt.subkeys (
--
-- 
       skKey serial primary key,
       skPid text not null,
       skId text not null unique,
       skUsed boolean default False
);

CREATE OR REPLACE FUNCTION rmt.subkeysinsertTF() returns trigger as $$
  --
  -- Forces our value of skid
  -- Deactives previous entries for this pid
  --
  DECLARE
  BEGIN
    new.skid=md5(now()::text||random()::text);
    UPDATE rmt.subkeys SET skUsed=True WHERE skpid=NEW.skpid and skkey != NEW.skkey;
    RETURN NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.subkeysinsertTF() OWNER TO lsadmin;

CREATE TRIGGER subkeyInsertTrigger BEFORE INSERT on rmt.subkeys FOR EACH ROW EXECUTE PROCEDURE rmt.subkeysInsertTF();


CREATE OR REPLACE FUNCTION rmt.subkeysget() returns text as $$
  INSERT INTO rmt.subkeys default values;
  SELECT skId FROM rmt.subkeys WHERE skKey=currval( 'rmt.subkeys_skkey_seq');
$$ LANGUAGE sql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.subkeysget() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.subkeyOK( theSkid text) returns boolean as $$
  DECLARE
    rtn boolean;
  BEGIN
    SELECT skUsed INTO rtn FROM rmt.subkeys WHERE skid=theSkid;
    IF rtn THEN
      UPDATE rmt.subkeys set skUsed = False WHERE skid=theSkid;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.subkeyOK( text) OWNER TO lsadmin;


CREATE TABLE rmt.subbieFanout(
       sfKey serial primary key,
       sfInput text NOT NULL,
       sfFunc  text NOT NULL
);
ALTER TABLE rmt.subbieFanout OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.maybeRunSubbie( pid text) returns text AS $$
  DECLARE
    theSubbie text;     -- The subbie to run
    rtn text;
  BEGIN
    --
    -- Is there a subbie request?
    --
    SELECT rmt.getSubbieLiveVar( pid) INTO theSubbie;
    IF theSubbie IS NOT NULL and len( theSubbie) > 0 THEN
      --
      -- See if subbie is allowed to run
      -- is false if subkey has been superseeded or if it has already been run.
      --
      IF rmt.subkeyOK( rmt.getLiveVar( pid, 'global_subkey')) THEN
        EXECUTE theSubbie || '(' || pid || ')' INTO rtn;
      END IF;
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.maybeRunSubbie( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.xmlrmt( pid text) returns text as $$
  DECLARE
    theRole text;
  BEGIN
    SELECT pRole INTO theRole FROM rmt.pids WHERE pPid=pid;
    IF NOT FOUND THEN
      RETURN rmt.xmlNone( pid);
    ELSIF theRole = 'RemoteUser' THEN
      RETURN rmt.xmlRemote( pid);
    END IF;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlrmt( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.xmlrolesnh( pid text) returns text as $$
  DECLARE
    rtn text;
    r   text;
    cr  text;   -- current role
    cu  text;   -- current user
  BEGIN
    SELECT pRole, pUid INTO cr, cu FROM rmt.pids WHERE pPid=pid;
    rtn := '<roles currentRole="'|| cr || '" currentUser="' || cu || E'">\n';
    FOR r IN SELECT 'RemoteUser' LOOP
      rtn := rtn || '<role value="' || r || E'"/>\n';
    END LOOP;
    rtn := rtn || E'</roles>\n';
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlrolesnh( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.xmlEsafnh( pid text) returns xml as $$
  --
  -- Called by https://rmt.ls-cat.org/esafs
  --
  DECLARE
    rtn xml;
    tmp xml;
    eid int;
    esd date;
    et text;
    fst text;
    fnd boolean;
    pfn text;
    pln text;
    pinst text;
    runstart timestamptz;
  BEGIN

    SELECT rmt.getLiveVar( pid, 'global_esaf') INTO et;
    IF NOT FOUND or et IS NULL THEN
      et := '0';
    END IF;

    SELECT INTO runstart srnstart FROM lsched.syncrunnames WHERE srnstart < (now() + '2 weeks'::interval) and srnname not like '%own%' ORDER BY srnstart DESC LIMIT 1;

    fst := '';
    fnd := False;
    FOR eid, esd IN SELECT distinct peexperiment, eidstartdate
          FROM esaf._peopleexperiments
          LEFT JOIN esaf._people ON peperson=pkey
          LEFT JOIN esaf.esafs ON eexperimentid=peexperiment
          LEFT JOIN rmt.pids ON (pBdg=pbadgeno or prole='Staff')
          WHERE pPid=pid and eBLApproverName is not null and eidstartdate >= runstart
          ORDER BY eidstartdate DESC
          LOOP

      IF fst = '' THEN
        fst := eid;
      END IF;
      IF fst::int = eid THEN
        fnd := True;
      END IF;
      IF et = '0' THEN
        et := eid;
        PERFORM rmt.setLiveVars( pid, 'global_esaf', et);
      END IF;
      SELECT expfn, expln, expinst INTO pfn, pln, pinst FROM esaf.experimenter WHERE expexperimentid=eid and expspokesperson='Y';
      IF NOT FOUND THEN
        pfn='';
        pln='';
        pinst='';
      END IF;
      tmp = xmlconcat( tmp, xmlelement( name esaf, xmlattributes( eid as id, esd as startdate, pfn as pifn, pln as piln, pinst as piinst)));
    END LOOP;

    IF not fnd THEN
      et := fst;
      PERFORM rmt.setLiveVars( pid, 'global_esaf', et);
    END IF;

    rtn = xmlelement( name esafs, xmlattributes( et as current), tmp);

    IF et = '0' THEN
      PERFORM rmt.setLiveVars( pid, 'esaf_prefix', '0');
      PERFORM rmt.setLiveVars( pid, 'snapNorm', '');
      PERFORM rmt.setLiveVars( pid, 'currentShot', '');
    END IF;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlEsafnh( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.xmlEsafStnnh( pid text) returns text as $$
  DECLARE
    rtn text;
    tmp text;
    esd date;
    stnvar text;
    stnnum int;
    stnn text;
    et  text;
    fnd boolean;
    fst text;
  BEGIN

    -- need the esaf to find the correct stations
    SELECT rmt.getLiveVar( pid, 'global_esaf') INTO et;
    IF NOT FOUND or et IS NULL THEN
      et := '0';
    END IF;

    SELECT rmt.getLiveVar( pid, 'esaf_station') INTO stnvar;
    IF NOT FOUND or stnvar IS NULL THEN
      stnvar := '0';
    END IF;

    tmp := '';
    fst := '';
    fnd := False;

    FOR stnnum, stnn IN SELECT distinct dsstn, stnname
          FROM px.datasets
          LEFT JOIN px.stations ON stnkey=dsstn
          WHERE dsesaf=et
          ORDER BY stnname
          LOOP

      IF fst = '' THEN
        fst := stnnum::text;
      END IF;

      IF stnvar = stnnum THEN
        fnd := True;
      END IF;

      IF stnvar='0' THEN
        stnvar := stnn;
        PERFORM rmt.setLiveVars( pid, 'esaf_station', stnvar);
      END IF;
      tmp = tmp || '  <station id="' || stnnum || '" name="' || stnn || E'"/>\n';
    END LOOP;

    IF not fnd THEN
      stnvar := fst;
      PERFORM rmt.setLiveVars( pid, 'esaf_station', stnvar);
    END IF;

    rtn := E'<stations current="' || stnvar || E'">\n';
    rtn := rtn || tmp;
    rtn := rtn || E'</stations>\n';

    IF stnvar = '0' THEN
      PERFORM rmt.setLiveVars( pid, 'esaf_prefix', '0');
      PERFORM rmt.setLiveVars( pid, 'snapNorm', '');
      PERFORM rmt.setLiveVars( pid, 'currentShot', '');
    END IF;

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlEsafStnnh( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.xmlPrefixSearch( expid int, ss text) returns XML as $$
  DECLARE
    rsult xml;
    p text;
    rtn xml;
  BEGIN
    FOR p, rsult IN SELECT dspid, xmlelement( name prefix, xmlattributes(dspid, dsdir  as path, dsdir || '/' || dsfp as label))
       FROM px.datasets
       WHERE dsesaf=expid and dsfp like ss || '%'
       LOOP
      PERFORM 1 FROM px.shots WHERE sdspid=p and sstate='Done';
      IF FOUND THEN
        rtn := xmlconcat( rtn, rsult);
      END IF;
    END LOOP;
    return xmlelement( name "searchResult", rtn);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlPrefixSearch( int, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.xmlDspidnh( thePid text) returns XML as $$
  DECLARE
    rtn xml;
    tmp1 xml;
    tmp2 xml;
    theShot record;
    pf text;
  BEGIN
    SELECT dsfp INTO pf FROM px.datasets WHERE dspid=thePid;
    FOR theShot in SELECT * FROM px.shots WHERE sdspid=thePid and sstate='Done' and length(coalesce(sbupath,''))>0 order by stype desc,sindex asc LOOP
      tmp1 = xmlelement( name file, xmlattributes( theShot.skey as skey, theShot.sfn as label, theShot.spath as path, theShot.sbupath as "buPath"));
      tmp2 = xmlconcat( tmp2, tmp1);
    END LOOP;
    rtn := xmlelement( name prefix, xmlattributes( 'true' as success, thePid as dspid, pf as label, extract( epoch from now()) as ts), tmp2);
    return rtn;
  END;

$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlDspidnh( text) OWNER TO lsadmin;


DROP FUNCTION rmt.xmlsubdirsnh( int, text);
CREATE OR REPLACE FUNCTION rmt.xmlSubDirsnh( expid int, theDir text) returns xml as $$
  DECLARE
    rtn xml;                    -- return document
    tmp xml;                    -- accumulates <dir/> and <prefix/> elements
    tmp1 xml;
    tmp2 xml;
    tmp3 xml;
    fileFound boolean;
    fileFound2 boolean;
    subdp text;
    subd text;
    subsubd text;
    pf text;
    subpf text;
    thePid text;
    theSubPid text;
    nf int;
    theKey int;
    theKey2 int;
    fn text;
    fn2 text;
    cmp text;
    pathName text;
    pathName2 text;
    buPathName text;
    buPathName2 text;
    theLevel int;
    nkids int;          -- number of children for this prefix  (>1 means treat as dir)
  BEGIN
    IF theDir is null THEN
      return xmlelement( name dirs, xmlattributes( 'false' as success, 'Path is null' as msg));
    END IF;

    theLevel := length(theDir) - length( replace( theDir, '/', '')) + 1;

    tmp := NULL;
    --
    -- loop over datasets matching this directory and esaf
    --
    FOR thePid, pf, nkids IN SELECT distinct dspid, dsfp, array_length( dspositions, 1)
                        FROM px.datasets
                        WHERE dsesaf=expid and dsdir=theDir and dsparent is null and dspid is not null and dsfp is not null
                        ORDER BY dsfp
                      LOOP

      tmp1 := NULL;
      IF nkids = 1 THEN
        --
        -- Search for exposures
        --
        tmp2 := NULL;
        FOR theKey, fn, pathName, buPathName IN SELECT skey, sfn, spath, sbupath
                                                FROM px.shots
                                                WHERE sdspid=thePid and sstate='Done' and sfn is not null and spath is not null
                                                      and sbupath is not null and length( sbupath)>0
                                                ORDER BY skey asc
                                             LOOP


          tmp2 := xmlconcat( tmp2, xmlelement( name file, xmlattributes( theKey as skey, fn as label, pathname as path, buPathName as "buPath")));
        END LOOP;
        IF tmp2 is not null THEN
          tmp1 := xmlconcat( tmp1, xmlelement( name prefix, xmlattributes( thePid as dspid, pf as label), tmp2));
        END IF;
      ELSE
        --
        --  Perhaps this prefix is just a parent for others
        --
        tmp2 := NULL;
        FOR theSubPid, subpf IN SELECT DISTINCT dspid, dsfp
                                FROM px.datasets
                                WHERE dsparent = thePid and dspid is not null and dsfp is not null
                                ORDER BY dsfp
                              LOOP
          tmp3 := NULL;
          FOR theKey2, fn2, pathName2, buPathName2 IN SELECT skey, sfn, spath, sbupath
                                                      FROM px.shots
                                                      WHERE sdspid=theSubPid and sstate='Done' and sfn is not null and spath is not null
                                                            and sbupath is not null and length( sbupath)>0
                                                      ORDER BY skey asc
                                                   LOOP
            tmp3 := xmlconcat( tmp3, xmlelement( name file, xmlattributes( thekey2 as skey, fn2 as label, pathname2 as path, bupathname2 as "buPath")));
          END LOOP;
          IF tmp3 is not null THEN
            tmp2 := xmlconcat( tmp2, xmlelement( name prefix, xmlattributes( theSubPid as dspid, subpf as label), tmp3));
          END IF;
        END LOOP;
        tmp1 := xmlconcat( tmp1, tmp2);
        --tmp1 := xmlconcat( tmp1, xmlelement( name dir, xmlattributes( pf as label, pf as path), tmp2));
      END IF;
      IF tmp1 is not null THEN
        tmp := xmlconcat( tmp, xmlelement( name prefix, xmlattributes( thePid as dspid, pf as label)), tmp1);
      END IF;
    END LOOP;

    IF theLevel = 1 THEN
      cmp := '%';
    ELSE
      cmp := '/%';
    END IF;

    IF theDir = '' THEN
      FOR subd IN SELECT distinct split_part(dsdir,'/',theLevel)
                    FROM px.datasets
                    WHERE dsesaf=expid and dsdir like theDir || cmp and dsdir is not null 
                    and length(split_part(dsdir,'/',theLevel))>0 LOOP
        IF subd is null THEN
          CONTINUE;
        END IF;

        tmp := xmlconcat( tmp, xmlelement( name dir, xmlattributes( subd as label, subd as path)));
      END LOOP;
    ELSE
      FOR subd IN SELECT distinct split_part(dsdir,'/',theLevel+1)
                           FROM px.datasets
                           WHERE dsesaf=expid and dsdir like theDir || cmp and dsdir is not null 
                                 and length(split_part(dsdir,'/',theLevel+1))>0 LOOP
        IF subd is null THEN
          CONTINUE;
        END IF;

        tmp := xmlconcat( tmp, xmlelement( name dir, xmlattributes( subd as label, theDir || '/' || subd as path)));
      END LOOP;
    END IF;

    rtn := xmlelement( name dirs, xmlattributes( 'true' as success, theDir as root, extract( epoch from now()) as ts), tmp);

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.xmlSubDirsnh( int, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.xmlDirs( pid text) returns text as $$
  DECLARE
    rtn text;
    theEsaf record;
    theUid text;
    theDir text;
    subds text;
    et text;            -- esaf experimentid in text form
  BEGIN 
    SELECT puid INTO theUid FROM rmt.pids WHERE ppid = pid;
    IF NOT FOUND THEN
      RETURN '';
    END IF;



    rtn := E'<?xml version="1.0" encoding="UTF-8"?>\n';
    SELECT rmt.getLiveVar( pid, 'global_esaf') INTO et;
    IF NOT FOUND or et IS NULL THEN
      rtn := rtn || '<dirs></dirs>';
      return rtn;
    END IF;


    rtn := rtn || E'<dirs>\n';

    --
    --  leave as loop over a number of esafs for now inspite of the fact that only one esaf is ever selected
    --  This ensures that the Uid has permission to access that particular ESAF
    --  This fuction does not currently support staff overrides
    --
    FOR theEsaf IN SELECT * FROM rmt.getEsafs(theUid) WHERE esafexpid=et ORDER BY esafexpid desc LOOP
      rtn := rtn || '  <dir label="' || theEsaf.esafexpid || E'">\n';

      SELECT rmt.xmlSubDirsnh( theEsaf.esafexpid::int, '', 1) INTO subds;
      IF FOUND and subds is not null THEN
        rtn := rtn || subds;
      END IF;

      rtn := rtn || E'  </dir>\n';
    END LOOP;
    rtn := rtn || E'</dirs>\n';
    return rtn;
  END;  
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlDirs( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.xmlPrefixnh( pid text) returns text as $$
  DECLARE
    rtn text;
    tmp text;
    stnvar text;
    et  text;
    pidd text;
    pidl text;
    p  text;
    fst text;
    fnd boolean;
  BEGIN

    -- need the esaf to find the correct stations
    SELECT rmt.getLiveVar( pid, 'global_esaf') INTO et;
    IF NOT FOUND or et IS NULL or et='' THEN
      et := '0';
    END IF;

    SELECT rmt.getLiveVar( pid, 'esaf_station') INTO stnvar;
    IF NOT FOUND or stnvar IS NULL or stnvar='' THEN
      stnvar := '0';
    END IF;

    IF et != '0' or stnvar != '0' THEN
      SELECT rmt.getLiveVar( pid, 'esaf_prefix') INTO pidd;
      IF NOT FOUND or pidd IS NULL or pidd='' THEN
        pidd := '0';
      END IF;
    ELSE
      pidd := '0';
    END IF;

    tmp := '';
    fst := '';
    fnd := False;
    FOR p, pidl IN SELECT dsfp, dspid
        FROM px.datasets
        WHERE dsesaf=et and dsstn=stnvar
        ORDER BY dskey DESC
      LOOP
      IF fst = '' THEN
        fst := pidl::text;
      END IF;
      IF pidd = pidl THEN
        fnd := True;
      END IF;
      IF pidd = '0' THEN
        pidd := pidl;
        PERFORM rmt.setLiveVars( pid, 'esaf_prefix', pidd);
      END IF;
      tmp := tmp || '  <prefix value="' || p || '" pid="' || pidl || E'"/>\n';
    END LOOP;

    IF NOT fnd THEN
      pidd := fst;
      PERFORM rmt.setLiveVars( pid, 'esaf_prefix', pidd);
    END IF;      

    rtn := E'<prefixs current="' || pidd || E'">\n';
    rtn := rtn || tmp;
    rtn := rtn || E'</prefixs>\n';
    
    IF pidd = '0' THEN
      PERFORM rmt.setLiveVars( pid, 'snapNorm', '');
      PERFORM rmt.setLiveVars( pid, 'currentShot', '');
    END IF;

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlPrefixnh( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.xmlSnapNormnh( pid text) returns text as $$
  DECLARE
    rtn text;
    tmp text;
    pidd text;
    p  text;
    sn text;
    snl text;
    fst text;
    fnd boolean;
  BEGIN

    SELECT rmt.getLiveVar( pid, 'esaf_prefix') INTO pidd;
    IF NOT FOUND or pidd IS NULL THEN
      pidd := '0';
    END IF;

    IF pidd != '0' THEN
      SELECT rmt.getLiveVar( pid, 'snapNorm') INTO sn;
      IF NOT FOUND or sn IS NULL THEN
        sn := '';
      END IF;
    ELSE
      sn := '';
    END IF;

    tmp := '';
    fst := '';
    fnd := False;
    FOR snl IN SELECT DISTINCT stype
        FROM px.shots
        WHERE sdspid=pidd and sstate='Done'
        ORDER BY stype
      LOOP

      IF fst = '' THEN
        fst := snl;
      END IF;
      IF sn = snl THEN
        fnd := True;
      END IF;

      IF sn = '' THEN
        sn := snl;
        PERFORM rmt.setLiveVars( pid, 'snapNorm', sn);
      END IF;
      tmp := tmp || '  <snapNorm value="' || snl || E'"/>\n';
    END LOOP;

    IF not fnd THEN
      sn := fst;
      PERFORM rmt.setLiveVars( pid, 'snapNorm', sn);
    END IF;

    rtn := E'<snapNorms current="' || sn || E'">\n';
    rtn := rtn || tmp;
    rtn := rtn || E'</snapNorms>\n';

    IF sn = '' THEN
      PERFORM rmt.setLiveVars( pid, 'currentShot', '');
    END IF;

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlSnapNormnh( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.xmlShotsnh( pid text) returns text as $$
  DECLARE
    rtn text;
    tmp text;
    pidd text;
    p  text;
    et text;
    theUid text;
    sn text;
    f  text;
    srec record;
  BEGIN

    SELECT rmt.getLiveVar( pid, 'global_esaf') INTO et;
    IF NOT FOUND or et IS NULL THEN
      et := '0';
    END IF;

    IF et != '0' THEN
      SELECT rmt.getLiveVar( pid, 'esaf_prefix') INTO pidd;
      IF NOT FOUND or pidd IS NULL THEN
        pidd := '0';
      END IF;
    ELSE
      pidd := '0';
    END IF;

    SELECT rmt.getU( pid) INTO theUid;
    IF NOT FOUND or theUid IS NULL THEN
      theUid := 'Invalid User';
    END IF;
    

    IF pidd != '0' THEN
      SELECT rmt.getLiveVar( pid, 'snapNorm') INTO sn;
      IF NOT FOUND or sn IS NULL THEN
        sn := '';
      END IF;
    ELSE
      sn := '';
    END IF;

    IF sn != '' THEN
      SELECT rmt.getLiveVar( pid, 'currentShot') INTO f;
      IF NOT FOUND or f IS NULL THEN
        f := '';
      END IF;
    ELSE
      f := '';
    END IF;

    --    raise notice 'pidd: %, sn: %', pidd, sn;

    tmp := '';
    FOR srec IN SELECT skey, sindex, sfn, coalesce(sstart,0) as sstart, coalesce(swidth,dsowidth,0) as swidth, coalesce(sexpt,dsexp,0) as sexpt,
                       coalesce(sexpu,dsexpunit,'') as sexpu, coalesce(sphi,dsphi,0) as sphi, coalesce(somega,dsomega,0) as somega,
                       coalesce(skappa,dskappa,0) as skappa, coalesce(sdist,dsdist,0) as sdist, coalesce(snrg,dsnrg,0) as snrg, coalesce(scmt,dscomment,'') as scmt,
                       sstate, coalesce(sposition,dsposition,0) as sposition, sts, coalesce(dsdir,'') as dsdir,
                       coalesce(homeDirectory,'') as homeDirectory, coalesce(buDirectory,'') as buDirectory
        FROM px.shots
        LEFT JOIN px.datasets on dspid=sdspid
        LEFT JOIN rmt.getEsafs( theUid) on esafExpid=et
        WHERE sdspid=pidd and stype=sn and sstate='Done'
        ORDER BY sindex
      LOOP

      IF f = '' THEN
        f := srec.skey;
        PERFORM rmt.setLiveVars( pid, 'currentShot', f);
      END IF;

      tmp := tmp || '  <shot skey="' || srec.skey || '" sindex="' || srec.sindex || '"';
      tmp := tmp || ' sfn="' || srec.sfn || '" start="' || srec.sstart || '" swidth="' || srec.swidth || '"';
      tmp := tmp || ' sexpt="' || srec.sexpt || '" sexpu="' || srec.sexpu || '" sphi="' || srec.sphi || '"';
      tmp := tmp || ' somega="' || srec.somega || '" skappa="' || srec.skappa || '" sdist="' || srec.sdist || '"';
      tmp := tmp || ' snrg="' || srec.snrg || '" scmt="' || srec.scmt || '" sstate="' || srec.sstate || '"';
      tmp := tmp || ' sposition="' || srec.sposition || '" sts="' || srec.sts || '" dsdir="' || srec.dsdir || '"';
      tmp := tmp || ' homeDirectory="' || srec.homeDirectory || '" buDirectory="' || srec.buDirectory || E'"/>\n';
    END LOOP;
    rtn := E'<shots current="' || f || E'">\n';
    rtn := rtn || tmp;
    rtn := rtn || E'</shots>\n';
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlShotsnh( text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.xmlNone( pid text) returns text as $$
  DECLARE
    rtn text;
  BEGIN
    rtn = E'<?xml version="1.0" encoding="UTF-8"?>\n';
    rtn = rtn || E'<rmt>\n';
    rtn = rtn || rmt.xmlrolesnh(pid);
    rtn = rtn || E'</rmt>\n';
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER VOLATILE;
ALTER FUNCTION rmt.xmlNone( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.xmlRemote( pid text) returns text as $$
  DECLARE
    rtn text;
  BEGIN
    rtn = E'<?xml version="1.0" encoding="UTF-8"?>\n';
    rtn = rtn || E'<rmt>\n';
    rtn = rtn || rmt.xmlrolesnh(pid);
    rtn = rtn || rmt.xmlesafnh(pid);
    rtn = rtn || rmt.xmlesafstnnh(pid);
    rtn = rtn || rmt.xmlprefixnh(pid);
    rtn = rtn || rmt.xmlsnapnormnh(pid);
    rtn = rtn || rmt.xmlshotsnh(pid);
    rtn = rtn || E'</rmt>\n';
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.xmlRemote( text) OWNER TO lsadmin;


INSERT INTO rmt.editVars (evName, evDefault, evValid) values ('global_esaf',     '',  NULL);    -- auction end timestamp
INSERT INTO rmt.evACL (aclVar, aclRole, aclPerm) values ( 'global_esaf', 'RemoteUser',     'ReadWrite');

INSERT INTO rmt.editVars (evName, evDefault, evValid) values ('global_uid',     '',  NULL);     -- auction end timestamp
INSERT INTO rmt.evACL (aclVar, aclRole, aclPerm) values ( 'global_uid', 'RemoteUser',     'ReadWrite');

INSERT INTO rmt.editVars (evName, evDefault, evValid) values ('esaf_station',     '',  NULL);   -- auction end timestamp
INSERT INTO rmt.evACL (aclVar, aclRole, aclPerm) values ( 'esaf_station', 'RemoteUser',     'ReadWrite');

INSERT INTO rmt.editVars (evName, evDefault, evValid) values ('esaf_prefix',     '',  NULL);    -- auction end timestamp
INSERT INTO rmt.evACL (aclVar, aclRole, aclPerm) values ( 'esaf_prefix', 'RemoteUser',     'ReadWrite');

INSERT INTO rmt.editVars (evName, evDefault, evValid) values ('snapNorm',     '',  NULL);       -- auction end timestamp
INSERT INTO rmt.evACL (aclVar, aclRole, aclPerm) values ( 'snapNorm', 'RemoteUser',     'ReadWrite');

INSERT INTO rmt.editVars (evName, evDefault, evValid) values ('currentShot',     '',  NULL);    -- auction end timestamp
INSERT INTO rmt.evACL (aclVar, aclRole, aclPerm) values ( 'currentShot', 'RemoteUser',     'ReadWrite');


CREATE TYPE rmt.esafhdtype AS ( buDirectory text, esafExpid text, homeDirectory text);

CREATE OR REPLACE FUNCTION rmt.getEsafs( theuid text) returns setof rmt.esafhdtype as $$
if not GD.has_key( "ldap"):
    import ldap
    GD["ldap"] = ldap
ldap = GD["ldap"]
        
if not SD.has_key( "l"):
    l=ldap.initialize( "ldap://contrabass.ls-cat.org")
    l.bind_s( 'cn=admin,dc=ls-cat,dc=org', 'curolonge')
    SD["l"] = l
l = SD["l"]
try:
    l.whoami_s()
except ldap.SERVER_DOWN:
    l = ldap.initialize( "ldap://contrabass.ls-cat.org")
    l.bind_s( 'cn=admin,dc=ls-cat,dc=org', 'curolonge')
SD["l"] = l


class ldap2esafs:
    def __init__( self, theuid):
        self.ndx = -1
        self.rtn = []
        eptl = SD["l"].search_s("dc=esaf,dc=ls-cat,dc=org", ldap.SCOPE_SUBTREE, "(memberUid=%s)" % (str(theuid)), ["esafExpid", "homeDirectory", "buDirectory"])
        for e in eptl:
            self.rtn.append( ( e[1]["buDirectory"][0], e[1]["esafExpid"][0], e[1]["homeDirectory"][0]))

    def __iter__( self):
        return self;

    def next( self):
        self.ndx += 1
        if self.ndx >= len( self.rtn):
            raise StopIteration
        return self.rtn[self.ndx]


return ldap2esafs( theuid)
$$ LANGUAGE plpythonu SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.getEsafs( text) OWNER TO lsadmin;

CREATE TABLE rmt.isCmds (
       isc text not null primary key
);
ALTER TABLE rmt.isCmds OWNER TO lsadmin;
INSERT INTO rmt.isCmds (isc) VALUES ('jpeg');
INSERT INTO rmt.isCmds (isc) VALUES ('download');
INSERT INTO rmt.isCmds (isc) VALUES ('header');
INSERT INTO rmt.isCmds (isc) VALUES ('profile');
INSERT INTO rmt.isCmds (isc) VALUES ('tarball');

CREATE TABLE rmt.is (
       iskey serial primary key,                -- our key
       ists timestamptz default now(),          -- creation timestamp
       ispid text references rmt.pids (ppid),   -- request authentication
       isrqid text not null default '',         -- request id from client
       isesaf int not null default 0,           -- the esaf used to collect the data
       iscmd text not null references rmt.isCmds (isc), -- our command
       isip inet not null,                      -- ip address of requesting machine
       isport int not null,                     -- requesting port
       is_fn text not null,                     -- filename (an unused value is placed here for indexing)
       is_xsize int default 256,                -- image xsize in pixels
       is_ysize int default 256,                -- image ysize in pixels
       is_contrast int default 65535,           -- values of this and larger are made black
       is_wval int default 0,                   -- values of this and smaller are mde white
       is_x int not null default 0,             -- Upper left of original image
       is_y int not null default 0,             -- Upper left of original image
       is_width int not null default 4096,      -- width of original image to map
       is_height int not null default 4096,     -- heighth of original image to map
       is_pax int not null default 0,           -- x coordinate of profile point a
       is_pay int not null default 0,           -- y coordinate of profile point a
       is_pbx int not null default 0,           -- x coordinate of profile point b
       is_pby int not null default 0,           -- y coordinate of profile point b
       is_pw  int not null default 1,           -- width of profile integration
       is_ifn1 text default null,               -- filename 1 for indexing routine
       is_ifn2 text default null,               -- filename 2 for indexing routine
       is_dspid text default null,              -- Dataset dspid for tarball
       is_connection text default null,         -- rsync username@host.domain[:port]
       is_sourcedir text default null,          -- full path of the source
       is_destdir text default null             -- path of the destination on user's machine
);
ALTER TABLE rmt.is OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.isInsertTF() returns trigger as $$
  DECLARE
  BEGIN
    NOTIFY IMAGE_SERVER_REQUEST;
    RETURN NULL;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isInsertTF() OWNER TO lsadmin;

CREATE TRIGGER isInsertTrigger AFTER INSERT on rmt.is FOR EACH STATEMENT EXECUTE PROCEDURE rmt.isInsertTF();

CREATE TABLE rmt.isServers (
       iss serial primary key,          -- our key
       issTs timestamptz default now(), -- connection time stamp
       issResponseTs timestamptz default NULL,  -- last response to a notify
       issResponseCnt int default 0,            -- number of times host has responded to a notify
       issPopTs timestamptz default NULL,       -- last time a pop returned an entry
       issPopCnt int default 0,                 -- number of times host has received a pop
       issHost inet not null default inet_client_addr() unique, -- ip address of server
       issClientPid int not null default 0,     -- postgres client PID
       issInetdp int default 14853,     -- port inetd is listening on to start srever
       issActive boolean default true   -- true if server should be started
);
ALTER TABLE rmt.isServers OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.isInit() returns void as $$
  DECLARE
  BEGIN
    UPDATE rmt.isServers SET issTs=now(), issActive=true WHERE issHost=inet_client_addr();
    IF NOT FOUND THEN
      INSERT INTO rmt.isServers DEFAULT VALUES;
    END IF;
    LISTEN IMAGE_SERVER_REQUEST;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isInit() OWNER TO lsadmin;


--DROP FUNCTION rmt.isRqstJpeg( text, int, text, text, int, int, int, int, int, int, int, int);
CREATE OR REPLACE FUNCTION rmt.isRqstJpeg( a_pid text, a_port int, a_rqid text, a_fn text, a_xsize int, a_ysize int, a_contrast int, a_wval int, a_x int, a_y int, a_width int, a_height int) returns xml AS $$
  DECLARE
    rtn xml;
  BEGIN
    INSERT INTO rmt.is ( ispid, isrqid, iscmd, isip, isport, is_fn, is_xsize, is_ysize, is_contrast, is_wval, is_x, is_y, is_width, is_height) VALUES
                       (a_pid, a_rqid, 'jpeg', inet_client_addr(), a_port, a_fn, a_xsize, a_ysize, a_contrast, a_wval, a_x, a_y, a_width, a_height);
    return '<httpheaders Content-type="image/jpeg"/>'::xml;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstJpeg( text, int, text, text, int, int, int, int, int, int, int, int) OWNER TO lsadmin;

--DROP FUNCTION rmt.isRqstHeader( text, int, text, text);
CREATE OR REPLACE FUNCTION rmt.isRqstHeader( a_pid text, a_port int, a_rqid text, a_fn text) returns xml AS $$
  DECLARE
    rtn xml;
  BEGIN
    INSERT INTO rmt.is ( ispid, isrqid, iscmd, isip, isport, is_fn) VALUES (a_pid, a_rqid, 'header', inet_client_addr(), a_port, a_fn);
    return '<httpheaders Content-type="application/xml"/>'::xml;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstHeader( text, int, text, text) OWNER TO lsadmin;

--DROP FUNCTION rmt.isRqstDownload( text, int, text, bigint);
CREATE OR REPLACE FUNCTION rmt.isRqstDownload( a_pid text, a_port int, a_rqid text, a_skey bigint) returns xml AS $$
  DECLARE
    rtn xml;
    fn  text;
    bupath text;
  BEGIN
    SELECT sfn, sbupath INTO fn, bupath FROM px.shots WHERE rmt.checkShotAccess( a_pid, a_skey) and skey=a_skey;
    IF NOT FOUND or fn is null or length( fn) < 1 or bupath is null or length( bupath) <20 THEN
      return '<httpheaders/>'::xml;
    END IF;    
    rtn := xmlelement( name httpheaders, xmlelement( name httpheader, xmlattributes( 'Content-disposition' as name, 'attachment; filename=' || fn as val)));
    INSERT INTO rmt.is ( ispid, isrqid, iscmd, isip, isport, is_fn) VALUES (a_pid, a_rqid, 'download', inet_client_addr(), a_port, bupath);
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstDownload( text, int, text, bigint) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.isRqstTarball( a_pid text, a_port int, a_rqid text, a_dspid text) returns xml AS $$
  DECLARE
    rtn xml;
    fn text;
    dummyfn text;
  BEGIN
    PERFORM 1 WHERE rmt.checkDSAccess( a_pid, a_dspid);
    IF NOT FOUND THEN
      return '<httpheaders/>'::xml;
    END IF;
    SELECT INTO fn dsfp || '.tar.bz2' FROM px.datasets WHERE dspid=a_dspid;
    IF NOT FOUND THEN
      return '<httpheaders/>'::xml;
    END IF;
    --
    -- We need at least a valid file name to move on.  Really, we cannot make a tarball otherwise...
    --
    SELECT INTO dummyfn sbupath FROM px.shots WHERE sdspid=a_dspid and sbupath is not null ORDER BY sindex asc LIMIT 1;
    IF NOT FOUND THEN
      return '<httpheaders/>'::xml;
    END IF;
    
    rtn := xmlelement( name httpheaders, xmlelement( name httpheader, xmlattributes( 'Content-disposition' as name, 'attachment; filename=' || fn as val)));
    INSERT INTO rmt.is( ispid, isrqid, iscmd, isip, isport, is_fn, is_dspid) VALUES
                      (a_pid, a_rqid, 'tarball', coalesce(inet_client_addr(),'127.0.0.1'::inet), a_port, dummyfn, a_dspid);
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstTarball( text, int, text, text) OWNER TO lsadmin;

--DROP FUNCTION rmt.isRqstIndexing( text, int, text, bigint, bigint);
CREATE OR REPLACE FUNCTION rmt.isRqstIndexing( a_pid text, a_port int, a_rqid text, a_skey1 bigint, a_skey2 bigint) returns xml AS $$
  DECLARE
    bupath1 text;
    bupath2 text;
  BEGIN
    SELECT sbupath INTO bupath1 FROM px.shots WHERE rmt.checkShotAccess( a_pid, a_skey1) and skey=a_skey1;
    IF NOT FOUND or bupath1 is null or length( bupath1) <20 THEN
      return '<httpheaders/>'::xml;
    END IF;    
    SELECT sbupath INTO bupath2 FROM px.shots WHERE rmt.checkShotAccess( a_pid, a_skey2) and skey=a_skey2;
    IF NOT FOUND or bupath1 is null or length( bupath2) <20 THEN
      return '<httpheaders/>'::xml;
    END IF;    
    INSERT INTO rmt.is ( ispid, isrqid, iscmd, isip, isport, is_fn, is_ifn1, is_ifn2) VALUES (a_pid, a_rqid, 'indexing', inet_client_addr(), a_port, bupath1, bupath1, bupath2);
    return '<httpheaders Content-type="application/xml"/>'::xml;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstIndexing( text, int, text, bigint, bigint) OWNER TO lsadmin;

--DROP FUNCTION rmt.isRqstRsync( text, int, text, int, text, text, text);
CREATE OR REPLACE FUNCTION rmt.isRqstRsync( a_pid text, a_port int, a_rqid text, a_esaf int, a_src text, a_dst text, a_connection text) returns xml AS $$
  DECLARE
    newsrc text;
    newdst text;
    newcon text;
  BEGIN
    --
    -- sanitize inputs, hopefully.
    --
    SELECT INTO newcon regexp_replace( trim(a_connection), E'[^-._a-zA-Z0-9/@:]', '', 'g');     -- remove possible shell escapes
    SELECT INTO newsrc px.fix_dir( trim(a_src));                                                -- Same function created the directory
    SELECT INTO newdst regexp_replace( trim(a_dst), E'[''`\\\\]', '', 'g');                     -- Less restrictive of the user's machine

    IF length( newsrc) > 0 and length( newdst) > 0 and length(newcon) > 0 THEN
      SELECT INTO newsrc rmt.gethomedirectory(a_esaf) || '/' || newsrc;                         -- Turn relative HD in to an absolute one
      INSERT INTO rmt.is ( ispid, isrqid, iscmd, isip, isport, 
    END IF;
    return '<httpheaders Content-type="application/xml"/>';
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstRsync( text, int, text, int, text, text, text) OWNER TO lsadmin;

DROP FUNCTION rmt.isRqstProfile( text, int, text, text, int, int, int, int, int);
CREATE OR REPLACE FUNCTION rmt.isRqstProfile( a_pid text, a_port int, a_rqid text, a_fn text, a_ax int, a_ay int, a_bx int, a_by int, a_w int) returns xml AS $$
  DECLARE
    rtn xml;
  BEGIN
    INSERT INTO rmt.is ( ispid, isrqid, iscmd, isip, isport, is_fn, is_pax, is_pay, is_pbx, is_pby, is_pw) VALUES
        (a_pid, a_rqid, 'profile', inet_client_addr(), a_port, a_fn, a_ax, a_ay, a_bx, a_by, a_w);
    return '<httpheaders Content-type="application/xml"/>'::xml;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.isRqstProfile( text, int, text, text, int, int, int, int, int) OWNER TO lsadmin;

drop type rmt.isType cascade;

CREATE TYPE rmt.isType AS ( isuser text, isrqid text, isesaf int, iscmd text, isip inet, isport int, fn text, xsize int, ysize int, contrast int, wval int, x int, y int, width int, height int, pax int, pay int, pbx int, pby int, pw int, ifn1 text, ifn2 text, dspid text);

CREATE OR REPLACE FUNCTION rmt.popIs() returns rmt.isType as $$
  DECLARE
    rtn rmt.isType;
    tmp record;
    ndel int;
  BEGIN
    UPDATE rmt.isServers SET issResponseTs=now(), issResponseCnt = issResponseCnt + 1 WHERE issHost = inet_client_addr();
    DELETE FROM rmt.is WHERE ists < now() - '60 seconds'::interval;

    SELECT * INTO tmp FROM rmt.is LEFT JOIN rmt.pids ON ispid=ppid WHERE pactive and iskey is not null ORDER BY iskey ASC LIMIT 1;
    IF NOT FOUND THEN
      RETURN NULL;
    END IF;
    DELETE FROM rmt.is WHERE iskey=tmp.iskey;
    GET DIAGNOSTICS ndel = ROW_COUNT;
    IF ndel != 1 THEN
      --
      -- Here someone else has gotten here first
      -- Just shake it off
      --
      RETURN NULL;
    END IF;
    UPDATE rmt.isServers SET issPopTs=now(), issPopCnt = issResponseCnt + 1 WHERE issHost = inet_client_addr();


    rtn.isuser   = tmp.puid;
    rtn.isrqid   = tmp.isrqid;
    rtn.isesaf   = tmp.isesaf;
    rtn.iscmd    = tmp.iscmd;
    rtn.isip     = tmp.isip;
    rtn.isport   = tmp.isport;
    rtn.fn       = tmp.is_fn;
    rtn.xsize    = tmp.is_xsize;
    rtn.ysize    = tmp.is_ysize;
    rtn.contrast = tmp.is_contrast;
    rtn.wval     = tmp.is_wval;
    rtn.x        = tmp.is_x;
    rtn.y        = tmp.is_y;
    rtn.width    = tmp.is_width;
    rtn.height   = tmp.is_height;
    rtn.pax      = tmp.is_pax;
    rtn.pay      = tmp.is_pay;
    rtn.pbx      = tmp.is_pbx;
    rtn.pby      = tmp.is_pby;
    rtn.pw       = tmp.is_pw;
    rtn.ifn1     = tmp.is_ifn1;
    rtn.ifn2     = tmp.is_ifn2;
    rtn.dspid    = tmp.is_dspid;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.popIs() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.checkEsafAccess( esaf int, badge int) returns boolean as $$
  DECLARE
    tmp record;
  BEGIN
    --
    -- See if they are on the ESAF
    --
    PERFORM 1 FROM esaf._peopleexperiments LEFT JOIN esaf._people ON peperson=pkey WHERE pbadgeno=badge and peexperiment=esaf;
    IF FOUND THEN
      return true;
    END IF;
    --
    -- better take a closer look at what is going on
    --
    SELECT  * INTO tmp FROM rmt.pids WHERE pbdg=badge ORDER BY pkey DESC LIMIT 1;
    IF NOT FOUND OR NOT tmp.pactive THEN
      return false;
    END IF;
    --
    -- super users get everything but only if they exist
    --
    IF tmp.prole='Super' THEN
      PERFORM 1 FROM esaf.esafs WHERE eexperimentid=esaf;
      IF FOUND THEN
        return true;
      END IF;
      return false;
    END IF;
    --
    -- staff members get all but proprietary (unless they are on the ESAF in which case the first check would have returned true)
    --
    IF tmp.prole='Staff' THEN
      PERFORM 1 FROM esaf.esafs WHERE eexperimentid=esaf and eproprietaryflag='N';
      IF FOUND THEN
        return true;
     END IF;
    END IF;
    RETURN false;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.checkEsafAccess( int, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.checkEsafAccess( int, text) returns boolean as $$
  SELECT rmt.checkesafaccess( $1, pbdg) FROM rmt.pids WHERE ppid=$2;
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION rmt.checkEsafAccess( int, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.checkTokenAccess( pid text, token text) returns boolean as $$
  --
  -- here pid is the rmt schema pid and token is from the dspid column of px.datasets
  --
  DECLARE
    tmp record;
    badge int;
    esaf int;
  BEGIN
    SELECT pbdg INTO badge FROM rmt.pids WHERE ppid=pid and pactive;
    IF NOT FOUND THEN
      return false;
    END IF;

    SELECT dsesaf INTO esaf FROM px.datasets WHERE dspid=token;
    IF NOT FOUND THEN
      return false;
    END IF;

    return rmt.checkEsafAccess( esaf, badge);

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.checkTokenAccess( text, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.checkStnAccess( stn bigint, badge int) returns boolean as $$
  DECLARE
    esafaccess boolean;
  BEGIN
    PERFORM 1 FROM px.stnstatus left join esaf._peopleexperiments on ssesaf=peexperiment LEFT JOIN esaf._people ON peperson=pkey WHERE pbadgeno=badge and ssstn=stn;
    IF FOUND THEN
      return true;
    END IF;
    SELECT rmt.checkesafaccess( ssesaf, badge) INTO esafaccess FROM px.stnstatus WHERE ssstn=stn;
    IF FOUND and esafaccess THEN
      return true;
    END IF;
    return false;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER STABLE;
ALTER FUNCTION rmt.checkStnAccess( bigint, int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.checkStnAccess( stn bigint, pid text) returns boolean as $$
  DECLARE
    badge int;
    esafaccess boolean;
  BEGIN
    --
    -- get the badge number from the pid
    --
    SELECT pbdg INTO badge FROM rmt.pids WHERE ppid=pid and pactive;
    IF NOT FOUND THEN
      -- At least a badge number is needed
      return false;
    END IF;

    --
    -- Super users walk right in
    --
    PERFORM 1 FROM rmt.pids WHERE ppid=pid and prole='Super' and pactive;
    IF FOUND THEN
      return true;
    END IF;

    --
    -- So do staff
    --
    PERFORM 1 FROM rmt.pids WHERE ppid=pid and prole='Staff' and pactive;
    IF FOUND THEN
      return true;
    END IF;

    --
    -- See if this person is named on the ESAF of the requested station
    --
    PERFORM 1 FROM px.stnstatus left join esaf._peopleexperiments on ssesaf=peexperiment LEFT JOIN esaf._people ON peperson=pkey WHERE pbadgeno=badge and ssstn=stn;
    IF FOUND THEN
      return true;
    END IF;
    --
    -- This checks to see if the person has access to the esaf that is running on the requested station
    -- If this is different from the previous check then the difference is quite subtle.  One of these should
    -- be removed.
    SELECT rmt.checkesafaccess( ssesaf, badge) INTO esafaccess FROM px.stnstatus WHERE ssstn=stn;
    IF FOUND and esafaccess THEN
      return true;
    END IF;
    
    --
    -- See if anyone is logged in
    --
    PERFORM 1 FROM px.stnstatus WHERE ssstn=stn;
    IF NOT FOUND THEN
      --
      -- No one is logged in: is the user staff or superuser?
      --
      PERFORM 1 FROM rmt.pids WHERE ppid=pid and prole='Staff' and pactive;
      IF FOUND THEN
        return true;
      END IF;
    END IF;

    return false;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.checkStnAccess( bigint, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.checkDSAccess( pid text, theDspid text) returns boolean as $$
  DECLARE
    badge int;
    rtn boolean;
    esaf int;
  BEGIN
    rtn := False;
    select dsesaf INTO esaf FROM px.datasets WHERE dspid=theDspid;
    IF NOT FOUND THEN
      return FALSE;
    END IF;

    SELECT pbdg INTO badge FROM rmt.pids WHERE ppid=pid;
    IF NOT FOUND THEN
      return FALSE;
    END IF;

    SELECT rmt.checkEsafAccess( esaf, badge) INTO rtn;
    IF NOT FOUND THEN
      return FALSE;
    END IF;

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.checkDSAccess( text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.checkShotAccess( pid text, theSKey bigint) returns boolean as $$
  DECLARE
    badge int;
    esaf int;
    rtn boolean;
  BEGIN
    rtn := False;
    SELECT dsesaf INTO esaf FROM px.shots LEFT JOIN px.datasets on dspid=sdspid WHERE skey=theSkey;
    IF NOT FOUND THEN
      return FALSE;
    END IF;

    SELECT pbdg INTO badge FROM rmt.pids WHERE ppid=pid;
    IF NOT FOUND THEN
      return false;
    END IF;

    SELECT rmt.checkEsafAccess( esaf, badge) INTO rtn;
    IF NOT FOUND THEN
      return false;
    END IF;

    return rtn;
  END;

$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.checkShotAccess( text, bigint) OWNER TO lsadmin;


------------------------
---
-- REMOTE COMMAND SUPPORT
---
------------------------

DROP TABLE IF EXISTS rmt.rmtCmdCmds CASCADE;
CREATE TABLE rmt.rmtCmdCmds (
       rcccmds text primary key
);
ALTER TABLE rmt.rmtCmdCmds OWNER TO lsadmin;

INSERT INTO rmt.rmtCmdCmds (rcccmds) values ('create');
INSERT INTO rmt.rmtCmdCmds (rcccmds) values ('start');
INSERT INTO rmt.rmtCmdCmds (rcccmds) values ('pause');
INSERT INTO rmt.rmtCmdCmds (rcccmds) values ('stop');

DROP TABLE IF EXISTS rmt.rmtCmdStatus CASCADE;
CREATE TABLE rmt.rmtCmdStatus (
       rcs text primary key
);
ALTER TABLE rmt.rmtCmdStatus OWNER TO lsadmin;

INSERT INTO rmt.rmtCmdStatus (rcs) values ('Not Started');
INSERT INTO rmt.rmtCmdStatus (rcs) values ('Running');
INSERT INTO rmt.rmtCmdStatus (rcs) values ('Idle');
INSERT INTO rmt.rmtCmdStatus (rcs) values ('Paused');
INSERT INTO rmt.rmtCmdStatus (rcs) values ('Stopping');
INSERT INTO rmt.rmtCmdStatus (rcs) values ('Stopped');
INSERT INTO rmt.rmtCmdStatus (rcs) values ('Done');

DROP TABLE IF EXISTS rmt.rmtAllowedCmds CASCADE;
CREATE TABLE rmt.rmtAllowedCmds (
       racKey serial primary key,               -- our key
       racName text not null unique,            -- the name provided to the API
       racRoles text[] not null                 -- roles that are allowed to access this function
          default '{"remoteUser"}',
       racCmd text not null,                    -- the command we'll allow
       racArg0 text not null unique,            -- value to use as arg[0]
       racInit xml default '<racInit/>'::xml    -- Interface construction information
);
ALTER TABLE rmt.rmtAllowedCmds OWNER TO lsadmin;

INSERT INTO rmt.rmtAllowedCmds (racName, racCmd, racArg0, racRoles, racInit) VALUES ( 'rsync', '/pf/bin/lsRsync.py', 'lsRsync.py',
'{"RemoteUser", "MailInUser", "Staff", "Super"}'::text[],
'<racInit name="rsync" action="rsync">
  <racField name="esaf"        label="ESAF to use"           type="hidden" default="" value="" help="User''s ESAF"/>
  <racField name="src"         label="Source Directory"      type="text"   size="64" minSize="1" maxSize="256" default="" value="" help="Sub directory to transfer"/>
  <racField name="dst"         label="Destination Directory" type="text"   size="64" minSize="1" maxSize="256" value="" help="Sub directory on remote machine to send data to"/>
  <racField name="connection"  label="Connection"            type="text"   size="64" minSize="1" maxSize="256" default="user@machine[:port]" value="" help="Your username@yourComputer[:optionalPort]"/>
  <racField name="sshkey"      label="SSH Key"               type="label"  size="64" minSize="1" maxSize="256" value="" help="Insert into ~username/.ssh/authorized_keys file"/>
</racInit>'::xml
);

INSERT INTO rmt.rmtAllowedCmds (racName, racCmd, racArg0, racRoles, racInit) VALUES (
'roboProcess', '/pf/bin/lsProcess.py','lsProcess.py',
'{"Robo"}'::text[],
'<racInit name="roboProcess" action="roboProcess">
  <racField name="esaf"    label="ESAF to use" type="hidden" default="" value="" help="User''s ESAF"/>
  <racField name="dspid"   label="Data Set"    type="text" size="64" minSize="32" default="" value="" help="Dataset identifier"/>
</racInit>'::xml
);

DROP TABLE IF EXISTS rmt.rmtCmds CASCADE;
CREATE TABLE rmt.rmtCmds (
       rckey serial primary key,                -- our key
       rcRACmd text not null                    -- the command we'll be running
           references rmt.rmtAllowedCmds (racName),
       rcCmdId text not null unique,            -- unique identifer for this command
       rcCreateTS timestamptz default now(),    -- genesis
       rcCmdTS timestamptz default now(),       -- last command time stamp
       rcStatusTS timestamptz default now(),    -- last status time stamp
       rcProgressTS timestamptz default now(),  -- last progress time stamp
       rcHost inet default null,                -- host accepting the command
       rcUser text not null,                    -- name of user running the command
       rcPPID int default 0,                    -- PID of the controlling Process
       rcPUID int default -1,                   -- UID to run Process as
       rcPGID int default -1,                   -- GID to run Process as
       rcCmd text                               -- What we'd like the rsync process to do next
                references rmt.rmtCmdCmds (rcccmds) default 'start',
       rcStatus text                            -- status
                references rmt.rmtCmdStatus default 'Not Started',
       rcProgress int default 0,                -- percent done: <0 means indeterminate
       rcIn xml default null,                   -- program's input
       rcOut xml default null                   -- program's output: output for a program that is not in the Stopped state is an intermediate result
);
ALTER TABLE rmt.rmtCmds OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdSetOutput( a_cmdid text, a_output xml) returns void as $$
  DECLARE  
  BEGIN
    UPDATE rmt.rmtCmds SET rcOut = a_output WHERE rcCmdId=a_cmdid;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdSetOutput( text, xml) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdGetOutput( a_cmdid text) returns xml as $$
  DECLARE  
    rtn xml;
  BEGIN
   SELECT rcOut INTO rtn FROM rmt.rmtCmds WHERE rcCmdId=a_cmdid;
   return rtn;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdGetOutput( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdGetInput( a_cmdid text) returns xml as $$
  DECLARE  
    rtn xml;
  BEGIN
   SELECT rcIn INTO rtn FROM rmt.rmtCmds WHERE rcCmdId=a_cmdid;
   return rtn;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdGetInput( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdSetProgress( a_cmdid text, a_progress int) returns void as $$
  DECLARE  
  BEGIN
    UPDATE rmt.rmtCmds SET rcprogress = a_progress, rcprogressts = now() WHERE rcCmdId=a_cmdid;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdSetProgress( text, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdGetProgress( a_cmdid text) returns int as $$
  DECLARE  
    rtn int;
  BEGIN
   SELECT rcprogress INTO rtn FROM rmt.rmtCmds WHERE rcCmdId=a_cmdid;
   return rtn;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdGetProgress( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdGetStatus( a_cmdid text) returns text as $$
  DECLARE  
    rtn text;
  BEGIN
   SELECT rcstatus INTO rtn FROM rmt.rmtCmds WHERE rcCmdId=a_cmdid;
   return rtn;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdGetStatus( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.rmtCmdSetStatus( a_cmdid text, a_status text) returns void as $$
  DECLARE  
  BEGIN
    UPDATE rmt.rmtCmds SET rcstatus = a_status, rcstatusts = now() WHERE rcCmdId=a_cmdid;
 END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdSetStatus( text, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.rmtCmdInsertTF() returns trigger as $$
  DECLARE
  BEGIN
    NEW.rcCmdId=md5(now()::text||random()::text);
    return NEW;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.rmtCmdInsertTF() OWNER TO lsadmin;

CREATE TRIGGER rmtCmdInsertTrigger BEFORE INSERT on rmt.rmtCmds FOR EACH ROW EXECUTE PROCEDURE rmt.rmtCmdInsertTF();


CREATE OR REPLACE FUNCTION rmt.cmdRqstInit( a_pid text, a_rqid text, a_name text) returns xml AS $$
  DECLARE
    rtn xml;
  BEGIN
    SELECT racinit INTO rtn FROM rmt.rmtAllowedCmds LEFT JOIN rmt.pids ON racroles @> array[prole]  WHERE racName=a_name;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstInit( text, text, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.cmdRqstList( a_pid text, a_rqid text) returns xml AS $$
  DECLARE
    rtn xml;
    tmp xml;
    nam text;
  BEGIN
    tmp := NULL;
    FOR nam IN SELECT ((xpath( '/racInit/@name', racinit))[0])::text FROM rmt.rmtAllowedCmds LEFT JOIN rmt.pids ON racroles @> array[prole] WHERE ppid=a_pid LOOP
      tmp := xmlconcat( tmp, xmlelement( name command, xmlattributes( nam as name)));
    END LOOP;
    rtn := xmlelement( name commands, xmlattributes( a_rqid as rqid), tmp);
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstList( text, text) OWNER TO lsadmin;

------------------
------------------
------------------
------------------
------------------



CREATE OR REPLACE FUNCTION rmt.cmdRqstStart( a_pid text, a_in xml) returns xml AS $$
  DECLARE
    skeya int[];
    aok boolean;
    sdspida text[];     -- array of dspids to validate access
    dspida text[];      -- array of dspids to validate access
    theSdspid text;
    theEsaf int;
    esafCnt int;
    cmdId text;
    a_namea text[];
    a_name text;
    a_esafa text[];
    a_esaf int;
    p_badge int;
    p_username text;

  BEGIN

    IF a_in is null THEN
      return xmlelement( name "remoteCmdReturn", xmlattributes( 'false' as success, 'No input document found' as msg));
    END IF;

    SELECT xpath( '/remoteCmd/@func', a_in) INTO a_namea;
    IF NOT FOUND or a_namea is null or array_dims(a_namea) is null THEN
      return xmlelement( name "remoteCmdReturn", xmlattributes( 'false' as success, 'No function name found' as msg));
    END IF;
    a_name := (a_namea[1])::text;

    SELECT xpath( '/remoteCmd/argument[./@name="esaf"]/@value', a_in) INTO a_esafa;
    IF NOT FOUND or a_esafa is null THEN
      return xmlelement( name "remoteCmdReturn", xmlattributes( 'false' as success, 'ESAF not found' as msg));
    END IF;
    a_esaf := (a_esafa[1])::int;

    SELECT puid, pbdg INTO p_username, p_badge FROM rmt.pids WHERE rmt.checkEsafAccess( a_esaf, pbdg) and ppid=a_pid;
    IF NOT FOUND THEN
      return xmlelement( name "remoteCmdReturn", xmlattributes( 'false' as success, 'Access to this ESAF denied' as msg));
    END IF;

    INSERT INTO rmt.rmtCmds ( rcRACmd, rcuser, rcPUID, rcPGID, rcIn) VALUES ( a_name, p_username, p_badge, a_esaf*100, a_in);
    SELECT rcCmdId INTO cmdId FROM rmt.rmtCmds WHERE rcKey = currval('rmt.rmtcmds_rckey_seq');

    PERFORM rmt.pushCmdQueue( cmdId);


    return xmlelement( name "remoteCmdReturn", xmlattributes( 'true' as "success", cmdId as "cmdId"));
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstStart( text, xml) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.cmdRqstRoboProcess( thepid text) returns void as $$
  DECLARE
    esaf int;
    indoc xml;
    rpid text;

  BEGIN
    SELECT INTO esaf dsesaf FROM px.datasets WHERE dspid=thepid;
    SELECT INTO rpid rmt.getrobopid( esaf);
    IF NOT FOUND OR rpid is null THEN
      return;
    END IF;

    indoc = xmlelement( name "remoteCmd", xmlAttributes( 'roboProcess' as func),
                        xmlelement( name "argument", xmlAttributes( 'esaf'  as "name", esaf   as "value")),
                        xmlelement( name "argument", xmlAttributes( 'dspid' as "name", thepid as "value"))
            );

   PERFORM rmt.cmdRqstStart( rpid, indoc);

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstRoboProcess( text) OWNER TO lsadmin;



CREATE OR REPLACE FUNCTION rmt.cmdRqstStatus( a_pid text, a_cmdId text) returns xml AS $$
  DECLARE
    theCmd record;
  BEGIN
    SELECT * INTO theCmd FROM rmt.rmtCmds WHERE rcCmdId = a_cmdId;
    IF NOT FOUND THEN
      return xmlelement( name "remoteStatusReturn", xmlAttributes( 'false' as "success", 'Process not found' as "msg"));
    END IF;
    return xmlelement( name "remoteStatusReturn", xmlAttributes(
                                                    theCmd.rcRacmd      as "cmd",
                                                    theCmd.rcProgress   as "progress",
                                                    theCmd.rcStatus     as "state",
                                                    theCmd.rcUser       as "user",
                                                    theCmd.rcCreateTS   as "createTS",
                                                    theCmd.rcCmdTS      as "cmdTS",
                                                    theCmd.rcStatusTS   as "statusTS",
                                                    theCmd.rcProgressTS as "progressTS"
                                                  ),
                       theCmd.rcIn, xmlelement( name "remoteOutput", theCmd.rcOut)
                     );
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstStatus( text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.cmdRqstStatusList( a_pid text, a_esaf int, a_type text, a_state text) returns xml AS $$
  DECLARE
    tmp xml;
    r   record;
  BEGIN
    PERFORM 1 FROM rmt.pids WHERE ppid=a_pid and rmt.checkEsafAccess( a_esaf, pbdg);
    IF NOT FOUND THEN
      return xmlelement( name "remoteStatusReturn", xmlAttributes( 'false' as success, 'ESAF access denied' as msg));
    END IF;
    tmp := NULL;
    FOR r IN SELECT * FROM rmt.rmtCmds WHERE rcpgid=a_esaf*100 ORDER BY rccreatets LOOP
      tmp := xmlconcat( tmp, xmlelement( name "remoteStatusReturn", xmlAttributes( r.rcCmdId as "cmdId", r.rcracmd as cmd, r.rcProgress as "progress", r.rcStatus as "status", r.rcUser as "user")));
    END LOOP;
    return xmlelement( name "remoteListReturn", tmp);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstStatusList( text, int, text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.cmdRqstAction( a_pid text, a_cmdid text, a_action text) returns xml AS $$
  DECLARE
    cr record;	-- current record: used to keep from making the same request multiple times
  BEGIN

    --
    -- Make sure that two processes do not act on the same request at the same time
    -- This is to take care of the case where two processes try to simultaneously start
    -- the same command at the same time.
    --
    LOCK TABLE ONLY rmt.rmtCmds IN ACCESS EXCLUSIVE MODE;

    SELECT INTO cr * FROM rmt.rmtCmds WHERE rccmdid = a_cmdid;
    IF NOT FOUND THEN
      return xmlelement( name "remoteActionReturn", xmlattributes( 'false' as success, 'command not found ' || a_cmdid as msg));
    END IF;

    
    IF cr.rcCmd != a_action or cr.rccmdTS + '30 seconds'::interval < now() THEN
      --
      -- Force a wait before trying to make the same request again
      -- The delay should be long enough to ensure no race condition exists but short enough
      -- so that a command server restart does not cause too much consternation.
      --
      UPDATE rmt.rmtCmds SET rcCmd=a_action, rccmdTS=now() WHERE rcCmdId = a_cmdid;
      PERFORM rmt.pushCmdQueue( a_cmdid);
    END IF;

    return xmlelement( name "remoteActionReturn", xmlattributes( 'true' as success));

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdRqstAction( text, text, text) OWNER TO lsadmin;

DROP TABLE IF EXISTS rmt._cmdQueue CASCADE;
CREATE TABLE rmt._cmdQueue( 
       cqKey serial primary key,                        -- our key
       cqts timestamptz not null default now(),         -- time item entered into queue
       cqCmdId text not null                            -- pointer to the command
         references rmt.rmtCmds (rcCmdId)
);
ALTER TABLE rmt._cmdQueue OWNER TO lsadmin;

DROP TABLE rmt.cmdServers CASCADE;
CREATE TABLE rmt.cmdServers (
       csKey serial primary key,                -- our key
       csTs timestamptz default now(),  -- connection time stamp
       csResponseTs timestamptz default NULL,   -- last response to a notify
       csResponseCnt int default 0,             -- number of times host has responded to a notify
       csPopTs timestamptz default NULL,        -- last time a pop returned an entry
       csPopCnt int default 0,                 -- number of times host has received a pop
       csHost inet not null default inet_client_addr() unique,  -- ip address of server
       csClientPid int not null default 0,     -- postgres client PID
       csInetdp int default 14854,      -- port inetd is listening on to start srever
       csActive boolean default true    -- true if server should be started
);
ALTER TABLE rmt.cmdServers OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.cmdServerInit() returns void as $$
  DECLARE
  BEGIN
    UPDATE rmt.cmdServers SET csTs=now(), csActive=true WHERE csHost=inet_client_addr();
    IF NOT FOUND THEN
      INSERT INTO rmt.cmdServers DEFAULT VALUES;
    END IF;
    LISTEN REMOTE_COMMAND_SERVER_NEEDED;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.cmdServerInit() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.pushCmdQueue( a_cmdid text) returns void as $$
  DECLARE
  BEGIN
    LOCK TABLE ONLY rmt._cmdQueue IN ACCESS EXCLUSIVE MODE;
    INSERT INTO rmt._cmdQueue (cqCmdId) values (a_cmdid);
    NOTIFY REMOTE_COMMAND_SERVER_NEEDED;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.pushCmdQueue( text) OWNER TO lsadmin;

CREATE TYPE rmt.rmtcmdtype AS (rttracmd text, rttid text, rttuser text, rttuid int, rttgid int, rttcmd text, rttstatus text, rttprogress int, rttin xml, rttout xml);

CREATE OR REPLACE FUNCTION rmt.popCmdQueue() returns rmt.rmtcmdtype AS $$
  DECLARE
    theQkey bigint;
    theCmdId text;
    rtn rmt.rmtcmdtype;
    tmp record;
  BEGIN
    UPDATE rmt.cmdServers set csResponseTs=now(), csResponseCnt = csResponseCnt + 1 WHERE csHost=inet_client_addr();
    --
    -- Does an existing process need service?
    --

    LOCK TABLE ONLY rmt._cmdQueue IN ACCESS EXCLUSIVE MODE;

    SELECT cqKey, cqCmdId INTO theQkey, theCmdId FROM rmt._cmdQueue LEFT JOIN rmt.rmtCmds ON cqCmdId=rcCmdId WHERE rcHost = inet_client_addr() ORDER BY cqKey ASC LIMIT 1;
    IF NOT FOUND THEN
      --
      -- Does a new process need starting
      --
      SELECT cqKey, cqCmdId INTO theQkey, theCmdId FROM rmt._cmdQueue LEFT JOIN rmt.rmtCmds ON cqCmdId=rcCmdId WHERE rcHost is null LIMIT 1;
      IF NOT FOUND THEN
        return NULL;
      END IF;
    END IF;
    DELETE FROM rmt._cmdQueue WHERE cqKey = theQkey;
    UPDATE rmt.cmdServers set csPopTs=now(), csPopCnt = csPopCnt + 1 WHERE csHost=inet_client_addr();
    SELECT INTO tmp * FROM rmt.rmtcmds  WHERE rcCmdId = theCmdId;
    rtn.rttracmd    = tmp.rcracmd;
    rtn.rttid       = theCmdId;
    rtn.rttuser     = tmp.rcuser;
    rtn.rttuid      = tmp.rcpuid;
    rtn.rttgid      = tmp.rcpgid;
    rtn.rttcmd      = tmp.rccmd;
    rtn.rttstatus   = tmp.rcstatus;
    rtn.rttprogress = tmp.rcprogress;
    rtn.rttin       = tmp.rcin;
    rtn.rttout      = tmp.rcout;
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.popCmdQueue() OWNER TO lsadmin;

CREATE TABLE rmt.cams (
       ckey serial primary key,         -- our key
       cname text not null,             -- name of camera
       clocation text not null,         -- location of camera
       ctype text not null,             -- type of camera (brand/model)
       cCenterNotify text default NULL, -- name of notify event to listen for if this is a centering camera
       cfont text,                      -- name of font used for time stamp
       cstn bigint,                     -- -1 if conference cam, 0 if staff, otherwise station key
       cheight int not null,            -- full size height of image
       cwidth  int not null,            -- full size widty of image
       cjpeg text,                      -- url of jpeg
       cmjpeg text,                     -- url of mjpeg
       cmpeg4 text,                     -- url of mp4
       csetup text default null         -- url to call to set up the shot (for Axis PZT, for example)
);
ALTER TABLE rmt.cams OWNER TO lsadmin;       


CREATE TABLE rmt.feedcams (
       fckey serial primary key,                                -- our key
       fccam bigint not null references rmt.cams (ckey)         -- the camera
                             on delete cascade,
       fcfeed bigint not null references rmt.feeds (fkey)       -- the feed
                              on delete cascade,
       fcseq int not null                                       -- the sequence of cameras
);
ALTER TABLE rmt.feedcams OWNER TO lsadmin;

CREATE TABLE rmt.feeds (
       fkey serial primary key,         -- our key
       fname text not null,             -- the name
       fdescript text default '',       -- the description
       fuserstn int default 0,          -- If a user feed, specifies station that can view it
       fjpeg text,                      -- jpeg url
       fmjpeg text,                     -- mjpeg url
       fflv text,                       -- flv url
       fmpeg4 text                      -- mpeg4 url
);
ALTER TABLE rmt.feeds OWNER TO lsadmin;

CREATE TYPE rmt.camListType AS ( cljpeg text, clmjpeg text, clmpeg4 text, clseq int, clname text, cllocation text, cltype text, clheight int, clwidth int, clfont text, clcenternotify text);

CREATE OR REPLACE FUNCTION rmt.camlist( feedName text) RETURNS setof rmt.camListType AS $$
  DECLARE
    tmp record;
    rtn rmt.camListType;

  BEGIN
  
  FOR tmp IN SELECT * FROM rmt.feeds
                      LEFT JOIN rmt.feedcams ON fkey=fcfeed
                      LEFT JOIN rmt.cams ON fccam=ckey
                      WHERE fname=feedName ORDER BY fcseq
      LOOP

    rtn.cljpeg     = tmp.cjpeg;
    rtn.clmjpeg    = tmp.cmjpeg;
    rtn.clmpeg4    = tmp.fmpeg4;
    rtn.clseq      = tmp.fcseq;
    rtn.clname     = tmp.cname;
    rtn.cllocation = tmp.clocation;
    rtn.cltype     = tmp.ctype;
    rtn.clheight   = tmp.cheight;
    rtn.clwidth    = tmp.cwidth;
    rtn.clfont     = tmp.cfont;
    rtn.clcenternotify = tmp.ccenternotify;
    
    RETURN NEXT rtn;

  END LOOP;
  return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.camlist( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.nextStnCam( theStn bigint) RETURNS int AS $$
  DECLARE
    rtn int;
    st  int;
    ncams int;
  BEGIN
    ncams := 3;
    SELECT "State"  INTO st FROM cats.machinestate() WHERE "Station"=theStn;
    IF st & 512 > 0 THEN
      -- Robot is in exclusion zone
      -- Ceiling camera
      rtn = 1;
    ELSE
        SELECT CASE
          WHEN (st & 256) = 256 and (st & 512) = 0 THEN
            -- Timed camera feed
            floor(mod(10*(extract( second from now())/60)::numeric, ncams))::int + 1
          WHEN (st & 512) = 512  THEN
            -- Correct sample is mounted, robot is still running, look at mount area
            1
          ELSE
            -- 0, 128, and all other states: look at dewar overview
            2
        END
        INTO rtn;
    END IF;
    RETURN rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.nextStnCam( bigint) OWNER TO lsadmin;



CREATE TYPE rmt.nextFeedCamType AS (nfcc int, nfcsetup text);

CREATE OR REPLACE FUNCTION rmt.nextFeedCam( theFeedName text) returns rmt.nextFeedCamType AS $$
  --
  -- returns the sequence number of the camera to display in the feed
  -- currently only a feed name that is the same as the station data directory root (ie d,e,f or g)
  -- return a sequence number other than 1
  --
  DECLARE
    theStnKey bigint;
    rtn rmt.nextFeedCamType;
  BEGIN
    rtn.nfcc = 1;
    rtn.nfcsetup = '';
    
    SELECT INTO theStnKey stnkey FROM px.stations WHERE stndataroot=theFeedName;
    IF FOUND THEN
      SELECT INTO rtn.nfcc rmt.nextStnCam( theStnKey);
    END IF;

    SELECT INTO rtn.nfcsetup
                coalesce(csetup,'')
                FROM rmt.cams
                LEFT JOIN rmt.feedcams ON ckey = fccam
                LEFT JOIN rmt.feeds ON fcfeed  = fkey
                WHERE fcseq = rtn.nfcc
                  and fname=theFeedName;
    
    RETURN rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.nextFeedCam( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.feedCamSetups( theFeedName text) returns setof text AS $$
  SELECT coalesce(csetup,'') FROM rmt.cams LEFT JOIN rmt.feedcams ON ckey=fccam LEFT JOIN rmt.feeds ON fcfeed=fkey WHERE fname=$1;
$$ LANGUAGE SQL SECURITY DEFINER;
ALTER FUNCTION rmt.feedCamSetups( text) OWNER TO lsadmin;

CREATE TABLE rmt.feedServers (
       fskey serial primary key,                -- our key
       fsTs timestamptz default now(),          -- connection time stamp (set by SyncReader)
       fsResponseTs timestamptz default NULL,   -- last reponse to a notify
       fsResponseCnt timestamptz default NULL,  -- number of times host has received a pop
       fsNotify text not null,                  -- notify to use for SyncReader events
       fsHost inet not null default inet_client_addr() unique, -- ip of server
       fsClientPid int not null default 0       -- postgres client PID
);
ALTER TABLE rmt.feedServers OWNER TO lsadmin;

CREATE TABLE rmt.hostFeeds (
       -- link table between camera feeds and the machine 
       -- on which a SyncReader/SyncWriter is running on
       hfKey serial primary key,
       hfFeed bigint not null
             references rmt.feeds (fkey)
             on delete cascade,
       hfServer bigint not null
             references rmt.feedServers (fskey)
             on delete cascade
);
ALTER TABLE rmt.hostFeeds OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.syncWriterInit() returns setof text as $$
  -- Sets up server
  DECLARE
    rtn text;
  BEGIN
    FOR rtn IN SELECT fname
                      FROM rmt.hostFeeds
                      LEFT JOIN rmt.feeds ON hffeed=fkey
                      LEFT JOIN rmt.feedServers on hfServer=fskey
                      WHERE fsHost = inet_client_addr()
                      ORDER BY fname
    LOOP
      return next rtn;
    END LOOP;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.syncWriterInit() OWNER TO lsadmin;

CREATE TYPE rmt.trigCamType AS (tctName text, tctMjpeg text, tctFont text, tctNotify text);
CREATE OR REPLACE FUNCTION rmt.trigCamInit() returns setof rmt.trigCamType as $$
  DECLARE
    rtn rmt.trigCamType;
  BEGIN
    FOR rtn.tctNotify, rtn.tctName, rtn.tctMjpeg, rtn.tctFont IN SELECT DISTINCT ccenternotify, cname, cmjpeg, cfont
        FROM rmt.cams
        LEFT JOIN rmt.feedcams ON ckey=fccam
        LEFT JOIN rmt.feeds ON fkey=fcfeed
        LEFT JOIN rmt.hostfeeds ON hffeed=fkey
        LEFT JOIN rmt.feedServers ON fskey=hfServer
        WHERE fsHost=inet_client_addr()
          and ccenternotify is not null
      LOOP
        return next rtn;
    END LOOP;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.trigCamInit() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.syncReaderInit() returns setof text  as $$
  DECLARE
    ntfy text;
    rtn text;
  BEGIN
    UPDATE rmt.feedServers SET fsTs=now() WHERE fsHost=inet_client_addr();
    SELECT INTO ntfy fsNotify FROM rmt.feedServers WHERE fsHost=inet_client_addr();
    -- listen for instructions from user feeds
    EXECUTE 'LISTEN ' || ntfy;

    --
    -- return the list of camera feeds to respond to
    --
    FOR rtn IN SELECT fname
                      FROM rmt.hostFeeds
                      LEFT JOIN rmt.feeds ON hffeed=fkey
                      LEFT JOIN rmt.feedServers on hfServer=fskey
                      WHERE fsHost = inet_client_addr()
    LOOP
      return next rtn;
    END LOOP;
    return;

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.syncReaderInit() OWNER TO lsadmin;

CREATE TABLE rmt.userFeeds (
       ufkey serial primary key,                -- our key
       ufts timestamptz default now(),          -- creation time stamp
       ufpid text not null                      -- pid for remote user
             references rmt.pids (ppid)
             on delete cascade,
       ufhostServer bigint not null             -- server for this user
             references rmt.feedServers (fskey)
             on delete cascade,
       ufFeed bigint default null               -- current feed for this user (null = remove feed)
             references rmt.feeds (fkey)
             on delete cascade,
       ufHost inet not null,                    -- host requesting feed
       ufPort int not null                      -- port to send feed to
);
ALTER TABLE rmt.userFeeds OWNER TO lsadmin;

CREATE TABLE rmt.feedServerQueue (
       fsqKey serial primary key,
       fsts timestamptz not null default now(),
       fsqServer bigint not null
              references rmt.feedServers (fskey)
              on delete cascade,
       fsqUserFeed bigint not null
              references rmt.userFeeds (ufkey)
              on delete cascade
);
ALTER TABLE rmt.feedServerQueue OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.fsqpush( theServer bigint, theUserFeed bigint) returns void as $$
  DECLARE
    ntfy text;
  BEGIN
    INSERT INTO rmt.feedServerQueue (fsqServer, fsqUserFeed) values (theServer, theUserFeed);
    SELECT INTO ntfy fsNotify FROM rmt.feedServers WHERE fskey=theServer;
    EXECUTE 'NOTIFY ' || ntfy;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.fsqpush( bigint, text, bigint) OWNER TO lsadmin;
        
CREATE TYPE rmt.fsqpop_Type as (fptPid text, fptHost text, fptPort int, fptFeed text);
CREATE OR REPLACE FUNCTION rmt.fsqpop() returns rmt.fsqpop_type AS $$
  DECLARE
    rtn rmt.fsqpop_type;
    theUFKey bigint;
    theKey bigint;
  BEGIN
    SELECT INTO theKey, theUFKey fsqKey, fsqUserFeed FROM rmt.feedServerQueue left join rmt.feedServers on fsqServer=fskey WHERE fshost=inet_client_addr() ORDER BY fsqkey LIMIT 1;
    IF FOUND THEN
      DELETE FROM rmt.feedServerQueue WHERE fsqKey=theKey;
      SELECT INTO rtn.fptPid, rtn.fptHost, rtn.fptPort, rtn.fptFeed
                  ufpid,      ufHost,      ufPort,      fname
                  FROM rmt.userFeeds left join rmt.feeds on uffeed=fkey WHERE ufkey=theUFKey;
      return rtn;
    END IF;
    return NULL;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.fsqpop() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.endUserFeed( theHost inet, thePort int) returns void as $$
  DECLARE
    fs bigint;
    theFSKey bigint;
  BEGIN
    SELECT INTO theFSKey fskey FROM rmt.feedServers WHERE fsHost = inet_client_addr();
    DELETE FROM rmt.userFeeds
           WHERE ufHost=theHost
             and ufPort=thePort
             and ufHostServer=theFSKey
             and uffeed is null;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.endUserFeed( inet, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.startUserFeed( thePid text, theHost inet, thePort int, theFeed text) returns void as $$
  DECLARE
    theFSKey bigint;    -- the feed server key for the requested feed
    theFeedKey bigint;  -- the feed itself (or at least it's key)
    ntfy text;          -- the notify to send when done
  BEGIN
    -- Make sure we are authorized
    PERFORM 1 FROM rmt.checkpid(thePid);
    IF NOT FOUND THEN
      return;
    END IF;

    --
    -- find the feed and the server
    --
    SELECT INTO theFSKey, theFeedKey
                fskey,    fkey
                FROM rmt.feedServers
                LEFT JOIN rmt.hostFeeds on hfServer=fskey
                LEFT JOIN rmt.feeds on hfFeed=fkey
                WHERE fname=theFeed;
    IF NOT FOUND THEN
      return;
    END IF;
    
    --
    -- Cleanout old feeds from this user on this server
    --
    DELETE FROM rmt.userFeeds WHERE ufpid = thePid and ufhostServer=theFSKey;
    --
    -- save it and tell the server about it
    --
    INSERT INTO rmt.userFeeds (ufpid, ufhostServer, ufFeed, ufHost, ufPort) VALUES (thePid, theFSKey, theFeedKey, theHost, thePort);
    PERFORM rmt.fsqpush( theFSKey, currval( 'rmt.userFeeds_ufkey_seq'));

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.startUserFeed( text, inet, int, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.changeUserFeed( thePid text, theFeed text) returns void as $$
  -- thePid = user identifying hash
  -- theFeed = the name of the feed to view
  DECLARE
    theFSKey bigint;            -- the fskey for the new feed server
    theFeedKey bigint;          -- the fkey for the new feed
    theHost inet;
    thePort int;
    theUF record;               -- the old user feed record
  BEGIN
    PERFORM 1 FROM rmt.checkpid(thePid);
    IF NOT FOUND THEN
      return;
    END IF;
    
    SELECT INTO theUF * FROM rmt.UserFeeds WHERE ufpid = thePid and ufFeed is not null;
    IF NOT FOUND THEN
      raise notice 'no user feed found';
      -- What? A change to a non-existant user feed?
      return;
    END IF;

    --
    -- see if the new feed is on the same server
    --
    SELECT INTO theFSKey, theFeedKey
            fskey,    fkey
            FROM rmt.feedServers
            LEFT JOIN rmt.hostFeeds on hfServer=fskey
            LEFT JOIN rmt.feeds on hfFeed=fkey
            WHERE fname=theFeed;

    IF theFSKey = theUF.ufhostServer THEN
      raise notice 'changing feed on same server to feed %', thefeedkey;
      --
      -- just change the feed and let the server know
      --
      UPDATE rmt.UserFeeds SET ufFeed = theFeedKey where ufkey=theUF.ufKey;
      PERFORM rmt.fsqpush( theUF.ufhostServer, theUF.ufKey);
    ELSE
      raise notice 'starting new feed on new server';
      --
      -- let the server delete the feed
      --
      UPDATE rmt.UserFeeds SET ufFeed = NULL WHERE ufKey=theUF.ufKey;
      PERFORM rmt.fsqpush( theUF.ufHostServer, theUF.ufKey);

      --
      -- start a new feed with the same destination
      --
      PERFORM rmt.startUserFeed( thePid, theUF.ufHost, theUF.ufPort, theFeed);
    END IF;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.changeUserFeed( text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.feedListXML( thePid text) returns XML as $$
  DECLARE
    rtn xml;
    tmp xml;
    rslt record;
  BEGIN
    FOR rslt IN SELECT fname, fdescript
                  FROM px.stations
                  LEFT JOIN rmt.feeds ON stnkey = fuserstn
                  WHERE rmt.checkstnaccess( stnkey, thePid)
                  ORDER BY fdescript
                LOOP
      tmp := xmlconcat( tmp, xmlelement( name feed, xmlattributes( rslt.fname as fname, rslt.fdescript as label)));
    END LOOP;
    rtn = xmlelement( name feeds, xmlattributes( md5(tmp::text) as hash), tmp);
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.feedListXML( text) OWNER TO lsadmin;


CREATE TABLE rmt.screeningxferstyle (
       sxs text primary key
);
ALTER TABLE rmt.screeningxferstyle OWNER TO lsadmin;
INSERT INTO rmt.screeningxferstyle (sxs) VALUES ('ftp');
INSERT INTO rmt.screeningxferstyle (sxs) VALUES ('rsync');


CREATE TABLE rmt.screeningstates (
       ss text primary key
);
ALTER TABLE rmt.screeningstates OWNER TO lsadmin;
INSERT INTO rmt.screeningstates (ss) VALUES ('New');
INSERT INTO rmt.screeningstates (ss) VALUES ('Pending Acceptance');
INSERT INTO rmt.screeningstates (ss) VALUES ('Accepted');
INSERT INTO rmt.screeningstates (ss) VALUES ('Rejected');
INSERT INTO rmt.screeningstates (ss) VALUES ('Received');
INSERT INTO rmt.screeningstates (ss) VALUES ('Queued');
INSERT INTO rmt.screeningstates (ss) VALUES ('In Sample Changer');
INSERT INTO rmt.screeningstates (ss) VALUES ('Running');
INSERT INTO rmt.screeningstates (ss) VALUES ('Removed From Sample Changer');
INSERT INTO rmt.screeningstates (ss) VALUES ('Dewar Returned');
INSERT INTO rmt.screeningstates (ss) VALUES ('Done');

CREATE TABLE rmt.screeningCylinderTypes (
       sct text primary key,
       scto int unique
);
ALTER TABLE rmt.screeningCylinderTypes OWNER TO lsadmin;

INSERT INTO rmt.screeningCylinderTypes (sct, scto) VALUES ( 'SPINE Baskets', 1);
INSERT INTO rmt.screeningCylinderTypes (sct, scto) VALUES ( 'Rigaku Magazines', 2);
INSERT INTO rmt.screeningCylinderTypes (sct, scto) VALUES ( 'Canes', 3);
       

CREATE TABLE rmt.screeningForm (
       sfkey serial primary key,        -- our key
       sfHash text not null default md5(now()::text),
       sfcreatets timestamptz not null  -- creation time stamp
           default now(),
       sfupdatets timestamptz not null  -- most recent update
           default now(),
       sfState text not null default 'New' references rmt.screeningstates (ss),
       sfBadge int not null,            -- badge number of user
       sfemail text not null,           -- email address of the submitter
       sfphone text not null,           -- phone number of user
       sffax text default null,         -- fax number of user
       sfaddress text not null,         -- address to send dewar back to
       sfesaf int default null,         -- the corresponding esaf, if known
       sfInShipCompany text,            -- name of shipping company
       sfInDateShipped date             -- date shipped
           default null,
       sfInTrackingNumber text,         -- the Tracking Number
       sfOutShipCompany text,           -- name of shipping company
       sfOutDateShipped date            -- date shipped
            default null,
       sfOutTrackingNumber text,                -- the Tracking Number
       sfCylinderType text references rmt.screeningCylinderTypes (sct) default 'SPINE Baskets',

       sfXferStyle text default null    -- how to get the data back to the user
          references rmt.screeningxferstyle (sxs)
          on delete set null
          on update cascade,
       sfXferHost text default null,    -- host name to connection to
       sfXferDir text default null,     -- Directory name to dump stuff to
       sfXferUserName text              -- user name to use in transfers
          default null,
       sfXferPassword text              -- password to use
          default null,
       sfXferPrivateKey text            -- private key to use
          default null,
       sfXferPubKey text                -- public key to use
          default null
       
);
ALTER TABLE rmt.screeningForm OWNER TO lsadmin;

CREATE TABLE rmt.screeningProject (
       spKey serial primary key,        -- our key
       spsf bigint not null
            references rmt.screeningForm (sfkey)
            on delete cascade
            on update cascade,
       spIndex int not null,            -- project number 0 to n-1, unique for a given shippment
       spName text not null,            -- the name we'll call these samples
       spEsafName text not null,        -- the name used in the ESAF
       spInSize text default null,      -- how big the user thinks this is
       spInLength float default 18.0,   -- Length of pin in millimeters
       spInCella float default null,    -- Cell a in Ångstroms
       spInCellb float default null,    -- Cell b in Ångstroms
       spInCellc float default null,    -- Cell c in Ångstroms
       spInCellAlpha float default null,-- Cell alpha
       spInCellBeta  float default null,-- Cell beta
       spInCellGamma float default null,-- Cell gamma
       spInRes float default null,      -- We already have data to this resolution
       spInSpaceGroup text default null,-- The Space Group
       spInMosaicity float default null,-- Mosaicity
       spInRadSens text default null,   -- Perhaps the known radiation sensitivity
       spInEdge text                    -- Edge perhaps available
          default null,
       spDesiredRes text                -- Requested resolution
          default null,
       spDesiredCompletion text         -- Requested Completeness
          default null,
       spOutSize text default null,     -- how big the user thinks this is
       spOutLength float default 18.0,  -- Length of pin in millimeters
       spOutCella float default null,   -- Cell a in Ångstroms
       spOutCellb float default null,   -- Cell b in Ångstroms
       spOutCellc float default null,   -- Cell c in Ångstroms
       spOutCellAlpha float default null,-- Cell alpha
       spOutCellBeta  float default null,-- Cell beta
       spOutCellGamma float default null,-- Cell gamma
       spOutSpaceGroup text default null,-- The Space Group
       spOutMosaicity float default null,-- Mosaicity
       spOutRadSens text default null,  -- Perhaps the known radiation sensitivity
       spLambda1 float                  -- Perhaps what the user wants
          default null,
       spLambda2 float                  -- Perhaps what the user wants
          default null,
       spLambda3 float                  -- Perhaps what the user wants
          default null,
       spOutRes text                    -- Perhaps what the user wants
          default null,
       spOutComplete text               -- Perhaps what the user wants
          default null
);
ALTER TABLE rmt.screeningproject OWNER TO lsadmin;


CREATE TABLE rmt.screeningpuck (
       spkey serial primary key,        -- our key
       spsf bigint not null             -- the screening form
            references rmt.screeningForm (sfkey)
            on delete cascade
            on update cascade,
       spIndex int,                     -- the puck number (ei. 0-4)
       spId text                        -- Some sort of puck identifer
);
ALTER TABLE rmt.screeningpuck OWNER TO lsadmin;

CREATE TABLE rmt.screeningxtal (
       sxkey serial primary key,        -- our key
       sxsp bigint not null             -- the puck
            references rmt.screeningpuck (spkey)
            on delete cascade
            on update cascade,
       sxIndex int,                     -- xtal number (ie. 0-11)
       sxSpIndex int not null,          -- the project this crystal is part of
       sxId text                        -- Some sort of sample identifer
);
ALTER TABLE rmt.screeningxtal OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.setmailinform( thepid text, mf xml) returns xml as $$
  DECLARE
    thee xml;           -- the element we are inspecting
    theps xml;          -- the projects
    thecs xml;          -- the cylinders
    thebadge int;       -- the user's badge number
    thehash text;       -- the hash value to match an existing form
    thestate text;      -- the requested state
    thek text;
    thev text;
    qs text;
    qsa text;
    qsb text;

  BEGIN
    PERFORM 1 FROM rmt.checkpid( thePid);
    IF NOT FOUND THEN
      return xmlelement( name "MailinForm", xmlattributes( 'false' as success, 'Pease log in first' as msg));
    END IF;
    SELECT INTO thebadge pbdg FROM rmt.pids WHERE ppid = thepid;
    IF NOT FOUND THEN
      return xmlelement( name "MailinForm", xmlattributes( 'false' as success, 'Oddly, you do not exist' as msg));
    END IF;
    SELECT INTO thehash (xpath( '/MailinForm/sfhash/text()', mf))[1]::text;
    SELECT INTO thestate (xpath( '/MailinForm/sfstate/text()', mf))[1]::text;
    IF length( thehash) != 32 THEN
      thestate := 'New';
    END IF;
    IF thestate != 'New' THEN
      PERFORM 1 FROM rmt.screeningform WHERE sfhash=thehash;
      IF NOT FOUND THEN
        thestate := 'New';
      END IF;
    END IF;
    --
    -- set up both update and insert statements to avoid two loops or tons of IF's
    --
    qs := 'update rmt.screeningform set sfstate=' || quote_nullable(thestate);
    qsa := 'insert into rmt.screeningform (sfstate,sfbadge';
    qsb := ') values (' || quote_nullable(thestate) || ',' || thebadge;

    FOR thee IN SELECT unnest( xpath( '/MailinForm/*', mf)) LOOP
      SELECT INTO thek substring( thee::text from E'^<\(.*?\)/?>');

      IF thek is null or thek = 'sfhash' or thek = 'sfstate' or thek not like 'sf%' THEN
        CONTINUE;
      END IF;
      SELECT INTO thev coalesce((xpath('/MailinForm/' || thek || '/text()', mf))[1]::text, NULL);
      IF thev = '' THEN
        thev = NULL;
      END IF;
      IF thek is not null THEN
        qs  := qs  || ',' || quote_ident(thek) || '=' || quote_nullable( thev);
        qsa := qsa || ',' || quote_ident(thek);
        qsb := qsb || ',' || quote_nullable(thev);
      END IF;
    END LOOP;
    qsb := qsb || ')';
    IF thestate = 'New' THEN
      EXECUTE qsa || qsb;
      SELECT INTO thehash sfhash FROM rmt.screeningform WHERE sfkey=currval( 'rmt.screeningform_sfkey_seq');
    ELSE
      EXECUTE qs || ' where sfhash=' || quote_nullable( thehash);
    END IF;

    SELECT INTO theps (xpath( '/MailinForm/projects', mf))[1];
    IF theps is not null THEN
      PERFORM rmt.setproject( thehash, theps);
    END IF;

    SELECT INTO thecs (xpath( '/MailinForm/cylinders', mf))[1];
    IF thecs is not null THEN
      PERFORM rmt.setcylinders( thehash, thecs);    
    END IF;

    RETURN xmlelement( name "MailinForm", xmlattributes( 'true' as success, 'Operation successful' as msg), xmlelement( name sfhash, thehash));
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.setmailinform( text, xml) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.setproject( theHash text, projects xml) returns void as $$
  DECLARE
    project xml;        -- an extracted project from the projects xml document
    theSf bigint;       -- the screening form
    thepi int;          -- project index we are currently working with
    tmp text;           -- used to build the query string
    thek text;          -- the key
    thev text;          -- the value
    thee xml;           -- an element in the project
    qsA text;
    qsB text;
    qs  text;
  BEGIN
    SELECT INTO theSf sfkey from rmt.screeningform WHERE sfhash = thehash;
    IF NOT FOUND THEN
      return;
    END IF;
    FOR project IN SELECT unnest( xpath( '/projects/project', projects)) LOOP
      SELECT INTO thepi unnest( xpath( '/project/@projectIndex', project));
      IF FOUND THEN
        DELETE FROM rmt.screeningproject WHERE spsf=thesf and spindex=thepi;
      END IF;
      qsA := 'insert into rmt.screeningproject (spsf,spindex';
      qsB := ') values (' || thesf || ',' || thepi;

      FOR thee IN SELECT unnest( xpath('/project/*', project)) LOOP
        SELECT INTO thek substring( thee::text from E'^<\(.*?\)/?>');
        SELECT INTO thev (xpath('/project/'||thek||'/text()', project))[1]::text;
        IF thek is not null and thev is not null THEN
          qsA := qsA || ',' || quote_ident(thek);
          qsB := qsB || ',' || quote_nullable(thev);
        END IF;
      END LOOP;
      qsB := qsB || ')';
      qs := qsA || qsB;
      EXECUTE qs;
    END LOOP;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.setproject( text, xml) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.setcylinders( theHash text, cylinders xml) returns void as $$
  DECLARE
    cylinder xml;               -- extracted puck information
    xtal xml;                   -- extract cyrstal information
    thesf bigint;               -- screening form
    theci int;                  -- the cylinder index
    thecid text;                -- the cylinder id
    thespkey bigint;            -- a recently inserted puck
    thesxindex int;             -- sxindex of crystal
    thesxspindex int;           -- project index of this crystal
    thesxid text;               -- name (bar code) of this crystal
  BEGIN
    SELECT INTO theSf sfkey from rmt.screeningform WHERE sfhash = thehash;
    IF NOT FOUND THEN
      return;
    END IF;

    FOR cylinder IN SELECT unnest( xpath( '/cylinders/cylinder', cylinders)) LOOP
      SELECT INTO theci unnest( xpath( '/cylinder/@cylinderIndex', cylinder));
      IF FOUND THEN
        -- we'll replace the old values by first deleting them.  The xtal entries should vanish due to the casade in the definition
        DELETE FROM rmt.screeningpuck WHERE spsf=thesf and spindex=theci;
      END IF;
      SELECT INTO thecid (xpath( '/cylinder/spid/text()', cylinder))[1];
      INSERT INTO rmt.screeningpuck (spsf,spindex,spid) values ( thesf, theci, thecid);
      SELECT INTO thespkey currval( 'rmt.screeningpuck_spkey_seq');
      
      FOR xtal IN SELECT unnest( xpath( '/cylinder/xtal', cylinder)) LOOP
         SELECT INTO thesxindex   (xpath( '/xtal/sxindex/text()', xtal))[1];
         SELECT INTO thesxid      (xpath( '/xtal/sxid/text()', xtal))[1];
         SELECT INTO thesxspindex (xpath( '/xtal/sxspindex/text()', xtal))[1];
         INSERT INTO rmt.screeningxtal( sxsp, sxindex, sxspindex, sxid) VALUES ( thespkey, thesxindex, thesxspindex, thesxid);
      END LOOP;
    END LOOP;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.setcylinders( text, xml) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.screeningantidates() returns xml as $$
  --
  -- make up an xml document suitable for parsing out the Flex disabledRanges array for the DateChooser component
  -- We'll need n+1 ranges where n is the number of screening dates
  -- 
  DECLARE
    cb   date;          -- cbegin value
    ce   date;          -- cend value
    tmpe xml;           -- collect row values
    tmp2 xml;
    rtn xml;
    lastce date;
    df text;            -- date format string;
  BEGIN
    df := 'MM/DD/YYYY';
    lastce := NULL;
    FOR cb, ce IN SELECT cbegin::date, cend::date FROM lsched.anycal() WHERE clabel = 'Clinic' and cbegin::date >= now()::date ORDER BY cbegin LOOP
      IF lastce is null THEN
        -- The first range is open ended at the beginning so the user cannot ask for dates in the past
        --
        tmpe = xmlelement( name "disabledRange", xmlattributes( to_char((cb - '1 day'::interval)::date, df) as "rangeEnd"));
      ELSE
        IF lastce < cb THEN
          -- don't add a range if the next open slot is adjacent to the previous one.
          tmpe = xmlelement( name "disabledRange", xmlattributes( to_char((lastce + '1 day'::interval)::date,df)  as "rangeStart", to_char((cb - '1 day'::interval)::date,df) as "rangeEnd"));
        END IF;
      END IF;
      lastce := ce;
      tmp2 := xmlconcat( tmp2, tmpe);
    END LOOP;
    IF lastce is not null THEN
      tmpe = xmlelement( name "disabledRange", xmlattributes( to_char((lastce + '1 day'::interval)::date,df) as "rangeStart"));
      tmp2 := xmlconcat( tmp2, tmpe);
    END IF;
    rtn := xmlelement( name "disabledRanges", tmp2);
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.screeningantidates() OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.screeningdates() returns xml as $$
  DECLARE
    tmp xml;
    tmp2 xml;
    thestn text;
    thebegin text;
    theend text;
    thestaff text;
  BEGIN
    FOR thestn, thebegin, theend, thestaff IN SELECT cstn, cbegin, cend, cstaff FROM lsched.anycal() WHERE cbegin::date >= now()::date and clabel='Clinic' ORDER BY cbegin LOOP
      tmp := xmlconcat( tmp, xmlelement( name "screeningDate", xmlattributes( thestn as stn, thebegin as begin, theend as end, thestaff as staff)));
    END LOOP;
    tmp2 := rmt.screeningantidates();
    return xmlelement( name "screeningDates", tmp, tmp2);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.screeningdates() OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.setdiffmode( thepid text, thestn int, themode text) returns xml as $$
  DECLARE
    
  BEGIN
    PERFORM 1 where rmt.checkstnaccess( thestn, thepid);
    IF NOT FOUND THEN
      return xmlelement( name setdiffmode, xmlattributes( 'false' as success, 'Denied' as msg));
    END IF;

    UPDATE px.stnstatus SET ssmode=themode WHERE ssstn=theStn;
    return xmlelement( name setdiffmode, xmlattributes( 'true' as success));
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.setdiffmode( text, int, text) OWNER TO lsadmin;


CREATE TABLE rmt.usedNames (
--
-- Keep track of who has used which names
-- to forbid someone grabbing a user name
-- previously used by someone else
--
       unKey serial primary key,
       unBadge int not null,
       unName  text not null
);
ALTER TABLE rmt.usedNames OWNER TO lsadmin;

CREATE OR REPlACE FUNCTION rmt.nameOK( uname text, ubadge int) returns boolean AS $$
  --
  -- Return false if someone else has used this username before.
  -- This is to prevent privilege escalation by, say, a user grabbing
  -- a user name previously used by (and recognized as) a staff member.
  --
  DECLARE
  BEGIN
    PERFORM 1 FROM rmt.usedNames WHERE unname=uname and unbadge != ubadge;
    IF FOUND THEN
      return false;
    END IF;
    return true;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.nameOK( text, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.addToUsedNames( uname text, ubadge int) returns void AS $$
  BEGIN
    PERFORM 1 FROM rmt.usedNames WHERE unname=uname;
    IF NOT FOUND THEN
      INSERT INTO rmt.usedNames (unName, unBadge) VALUES (uname, ubadge);
    END IF;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.addToUsedNames( text, int) OWNER TO lsadmin;



CREATE TABLE rmt.centeringVideos (
--
-- Reference to stored centering videos 
--
       cvKey serial primary key,        -- Our Key
       cvTS timestamptz not null default now(),
       cvHash text not null unique      -- used to refer to this entry
              default md5(now()::text||random()::text),
       cvPath text not null,            -- Path to the video
       cvStn bigint,                    -- our station (should be a reference)
       cvESAF int,                      -- ESAF used to collect video
       cvUID int not null,		-- uid of esaf user
       cvGUI int not null,		-- gid of esaf user
       cvPosition int                   -- sample mounted
);
ALTER TABLE rmt.centeringVideos OWNER TO lsadmin;
CREATE INDEX centeringVideosStn  ON rmt.centeringVideos (cvStn);
CREATE INDEX centeringVideosESAF ON rmt.centeringVideos (cvESAF);

CREATE OR REPLACE FUNCTION rmt.centeringVideoInit( theStn int) returns text AS $$
  DECLARE
    curSam int;   -- currently mounted sample
    esaf  int;    -- current esaf
    theHash text; -- our hash value
    thePath text; -- centering video path
    ourKey bigint;
    theuid int;
    thegid int;
    centers_index int;
  BEGIN
    SELECT INTO esaf ssesaf FROM px.stnstatus WHERE ssstn = theStn;
    IF NOT FOUND THEN
      -- perhaps we are running without being logged in. Oh well.
      return NULL;
    END IF;

    
    -- prepare the new one
    SELECT INTO curSam coalesce(px.getCurrentSampleID( theStn),0);
    SELECT INTO theHash md5(now()::text || random()::text);
    SELECT INTO thePath rmt.getbudirectory( esaf) || '/centeringVideos/' || theHash;
    SELECT INTO theuid rmt.getuid( esaf);
    SELECT INTO thegid rmt.getgid( esaf);

    INSERT INTO rmt.centeringVideos (cvHash, cvPath, cvStn, cvESAF, cvPosition, cvuid, cvgid) VALUES (theHash, thePath, theStn, esaf, curSam, theuid, thegid);
    UPDATE px.stnstatus SET sscvhash=theHash WHERE ssstn=thestn;

    -- invalidate the current video hash
    centers_index = (coalesce( px.kvget( thestn, 'centers.editIndex'), '0'))::int;
    PERFORM px.kvset( thestn, 'centers.'||centers_index||'.hash', '');

    return theHash;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.centeringVideoInit( int) OWNER TO lsadmin;

CREATE TABLE rmt.hashvideotable (
       hvkey   serial primary key,		-- our key
       hvts timestamptz not null default now(), -- request time stamp
       hvbadge int not null,			-- badge number of user
       hvIp    inet not null,			-- ip of server waiting for the video
       hvPort  int not null,			-- port on server to connect to
       hvHash  text not null			-- hash of the video to send
);
ALTER TABLE rmt.hashvideotable OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.requestHashVideo( thePid text, serverIp inet, serverPort int, videoHash text) returns void as $$
  DECLARE
    badge int;		-- badge number for this user
  BEGIN
    PERFORM 1 WHERE rmt.checkpid( thePid);
    IF NOT FOUND THEN
      -- ignore illegal request
      return;
    END IF;

    SELECT INTO badge pbdg FROM rmt.pids WHERE ppid=thePid;
    IF NOT FOUND THEN
      -- This should not happen as we've already run checkpid
      return;
    END IF;

    INSERT INTO rmt.hashvideotable (hvbadge, hvip, hvport, hvhash) VALUES (badge, serverIp, serverPort, videoHash);
    NOTIFY REMOTE_HASH_VIDEO_SERVER_NEEDED;

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.requestHashVideo( text, inet, int, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.hashServerInit() returns setof text  as $$
  DECLARE
  BEGIN
    LISTEN REMOTE_HASH_VIDEO_SERVER_NEEDED;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.hashServerInit() OWNER TO lsadmin;


drop type rmt.hashvideotype cascade;
CREATE TYPE rmt.hashvideotype AS ( hash text, ip inet, port int, ts timestamptz, uid int, gid int, path text);

CREATE OR REPLACE FUNCTION rmt.getHashVideoRequest() RETURNS rmt.hashvideotype AS $$
  DECLARE
    rtn rmt.hashvideotype;
    theKey bigint;
    theHash text;
  BEGIN
    
    --
    -- get a request that is not too old
    -- This serves requests in the order received but ignores ones that are out of date.
    --
    SELECT INTO theKey, thehash, rtn.ip, rtn.port, rtn.ts, rtn.uid
                hvKey,  hvhash,   hvIp,   hvPort,   hvTs,   hvBadge
      FROM rmt.hashvideotable WHERE hvts >= now() - '30 seconds'::interval  ORDER BY hvkey LIMIT 1;
    IF NOT FOUND THEN
      RETURN NULL;
    END IF;

    -- Remove request
    DELETE FROM rmt.hashvideotable WHERE hvKey = theKey;

    --
    -- Get the GID: we'll read the video as the logged in user with the ESAF gid so that
    -- people can only see videos they have permission for even if they somehow get a valid hash
    -- for someone elses video
    --
    SELECT INTO rtn.gid, rtn.path cvgid, cvpath FROM rmt.centeringvideos WHERE cvhash = thehash;
    IF NOT FOUND THEN
      -- Not sure why anyone would request a non existent video 
      RETURN NULL;
    END IF;

    IF rtn.uid < 10000 or rtn.gid < 4026100 THEN
      --
      -- How did this user get here?  Don't let this be a back door
      -- for reading arbitrary files.
      --
      RETURN NULL;
    END IF;
    
    return rtn;

  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.getHashVideoRequest() OWNER TO lsadmin;



CREATE TYPE px.trigcamtype AS ( ip inet, port int, ts timestamptz, zoom int, startAngle float, speed float, fullpath text, esaf int, uid int, gid int);

CREATE OR REPLACE FUNCTION rmt.esafrunning( theesaf int) returns boolean AS $$
  DECLARE
  BEGIN
    PERFORM 1 FROM px.stnstatus WHERE ssesaf=theesaf;
    IF FOUND THEN
      return true;
    END IF;
    return false;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.esafrunning( int) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.getcenteringvideosxml( thePid text, esaf int) returns xml as $$
  DECLARE
    badge  int;
    gcvhash   text;
    gcvts     timestamp with time zone;
    gcvsam    int;
    rtn    xml;
    tmp    xml;

  BEGIN
    PERFORM 1 WHERE rmt.checkpid( thePid);
    IF NOT FOUND THEN
      return xmlelement( name centeringvideos, xmlattributes( 'false' as success, 'Access denied' as msg));
    END IF;
    SELECT INTO badge pbdg FROM rmt.pids WHERE ppid = thepid;
    IF NOT FOUND THEN
      return xmlelement( name centeringvideos, xmlattributes( 'false' as success, 'Access denied' as msg));
    END IF;
    PERFORM 1 WHERE rmt.checkesafaccess( esaf, badge);
    IF NOT FOUND THEN
      return xmlelement( name centeringvideos, xmlattributes( 'false' as success, 'Access denied' as msg));
    END IF;

    FOR gcvts, gcvhash, gcvsam IN SELECT cvts, cvhash, cvposition FROM rmt.centeringvideos WHERE cvesaf=esaf ORDER BY cvts desc LOOP
      tmp := xmlconcat( tmp, xmlelement( name centeringvideo, xmlattributes( gcvts as ts, gcvhash as hash, gcvsam as sample)));
    END LOOP;
    
    rtn := xmlelement( name centeringvideos, tmp);
    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.getcenteringvideosxml( text, int) OWNER TO lsadmin;


CREATE TABLE rmt.uistreams (
       uiskey serial primary key,	-- our key
       uists timestamptz default now(), -- creation time stamp
       uispid text not null		-- our browser
         references rmt.pids (ppid) on delete cascade on update cascade,
       uiskv int not null		-- the kv pair
         references px.kvs (kvkey) on delete cascade on update cascade,
       uisseq int not null default 0	-- sequence number: only send if current seq is > than this
);
ALTER TABLE rmt.uistreams OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.uisinit( thepid text, theStn int) returns void AS $$
  DECLARE
  BEGIN
    DELETE FROM rmt.uistreams USING px.kvs WHERE kvkey=uiskv and kvstn=theStn and uispid=thepid;
    INSERT INTO rmt.uistreams (uispid, uiskv) SELECT thepid, kvkey FROM px.kvs WHERE thestn=kvstn AND rmt.checkstnaccess( thestn, thepid);
    PERFORM px.autologinlisten( theStn);
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.uisinit( text, int) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.uisinit( thepid text) returns void AS $$
  DECLARE
    thestn int;
  BEGIN
    DELETE FROM rmt.uistreams WHERE uispid=thepid;
    INSERT INTO rmt.uistreams (uispid, uiskv) SELECT thepid, kvkey FROM px.kvs WHERE kvstn is null or kvstn=0;
    FOR thestn IN SELECT stnkey FROM px.stations LOOP
      PERFORM rmt.uisinit( thepid, thestn);
    END LOOP;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.uisinit( text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.uisreinit( thepid text, thenotify text) returns VOID as $$
  DECLARE
    thestn int;
  BEGIN
    SELECT INTO thestn cstnkey FROM px._config WHERE cnotifylogin=thenotify;
    IF FOUND THEN
      perform rmt.uisinit( thepid, thestn);
    END IF;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.uisreinit( text, text) OWNER TO lsadmin;


CREATE TYPE rmt.uistreamrtntype as (uisk text, uisv text, uisseq int);
CREATE OR REPLACE FUNCTION rmt.uistreamget( thepid text) returns setof rmt.uistreamrtntype AS $$
  DECLARE
    rtn rmt.uistreamrtntype;
    seq int;
    theuiskey int;
  BEGIN
    PERFORM 1 WHERE rmt.checkpidpassive( thepid);
    IF NOT FOUND THEN
      return;
    END IF;
    PERFORM px.kvspvupdate();
    FOR rtn.uisk, rtn.uisv, rtn.uisseq, theuiskey IN SELECT kvname, kvvalue, kvseq, uiskey FROM rmt.uistreams LEFT JOIN px.kvs ON uiskv=kvkey WHERE uispid=thepid and uisseq<kvseq LOOP
      RETURN NEXT rtn;
      UPDATE rmt.uistreams SET uisseq=rtn.uisseq WHERE uiskey=theuiskey;
    END LOOP;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

ALTER FUNCTION rmt.uistreamget( text) OWNER TO lsadmin;

CREATE TABLE rmt.kvcmdparamtypes (
       kvcmt text primary key
);
ALTER TABLE rmt.kvcmdparamtypes OWNER TO lsadmin;
INSERT INTO rmt.kvcmdparamtypes (kvcmt) VALUES ('int');
INSERT INTO rmt.kvcmdparamtypes (kvcmt) VALUES ('text');
INSERT INTO rmt.kvcmdparamtypes (kvcmt) VALUES ('numeric');
INSERT INTO rmt.kvcmdparamtypes (kvcmt) VALUES ('float');

drop table rmt.kvcmdparams;
CREATE TABLE rmt.kvcmdparams (
       kvcpkey serial primary key,	-- our key
       kvcpobj text not null,		-- will reference px.kvs (kvname) if it does not already (kv pair will be created if need be)
       kvcpcmd text not null,		-- the name of the command to call
       kvcpindex int not null,		-- index of this parameter
       kvcpname text not null,		-- name of this parameter: a kv pair based on this name will be created if need be
       kvcptype text not null		-- type of value expected
         references rmt.kvcmdparamtypes (kvcmt) ON DELETE CASCADE ON UPDATE CASCADE,
       kvcpdefault text default null,	-- value to use if none was provided
       UNIQUE (kvcpobj,kvcpcmd,kvcpindex)
);
ALTER TABLE rmt.kvcmdparams OWNER TO lsadmin;

INSERT INTO rmt.kvcmdparams (kvcpobj, kvcpcmd, kvcpindex, kvcpname, kvcptype, kvcpdefault) VALUES ( 'stns.0.centers', 'setcenter', '0', 'zoom', 'int', '1');
INSERT INTO rmt.kvcmdparams (kvcpobj, kvcpcmd, kvcpindex, kvcpname, kvcptype, kvcpdefault) VALUES ( 'stns.0.centers', 'setcenter', '1', 'dx',   'float',   '0.0');
INSERT INTO rmt.kvcmdparams (kvcpobj, kvcpcmd, kvcpindex, kvcpname, kvcptype, kvcpdefault) VALUES ( 'stns.0.centers', 'setcenter', '2', 'dy',   'float', '0.0');
INSERT INTO rmt.kvcmdparams (kvcpobj, kvcpcmd, kvcpindex, kvcpname, kvcptype, kvcpdefault) VALUES ( 'stns.0.centers', 'setcenter', '3', 'dz',   'float', '0.0');
INSERT INTO rmt.kvcmdparams (kvcpobj, kvcpcmd, kvcpindex, kvcpname, kvcptype, kvcpdefault) VALUES ( 'stns.0.centers', 'setcenter', '4', 'b',    'float', '0.0');
INSERT INTO rmt.kvcmdparams (kvcpobj, kvcpcmd, kvcpindex, kvcpname, kvcptype, kvcpdefault) VALUES ( 'stns.0.centers', 'setcenter', '5', 't0',   'float', '0.0');



CREATE OR REPLACE FUNCTION rmt.motionRequest( thePid text, theObj text, theCmd text, theParams text[]) returns void as $$
  --
  -- Should probably call this "md2_or_pv_motion_request"
  --
  DECLARE
    theStn int;		-- our station
    md2String text;	-- string to send to the md2
    thepvname text;     -- the pv (if any)
    themotion text;     -- the motion pv (see epics.motions)
    currentValue text;  -- current kv value of a pv
    theseq int;		-- new sequence number, if needed for pv
    motionOK boolean;   -- result of moveit
    arg1 text;		-- the first (and only?) for moving pvs
    params record;	-- parameters for this object/command
  BEGIN
    --
    -- make sure we are plausibly legal
    --
    PERFORM 1 WHERE rmt.checkpid( thepid);
    IF NOT FOUND THEN
      return;
    END IF;
    --
    -- Figure out which station we are dealing with
    --
    SELECT INTO theStn ((regexp_matches( theObj, E'^stns\.([0-9]+)\..+'))[1])::int;
    PERFORM 1 FROM px.stations WHERE stnkey=thestn;
    IF NOT FOUND or theStn is null THEN
      return;
    END IF;
    --
    -- make sure this user has access to this station
    --
    PERFORM 1 FROM rmt.checkstnaccess( theStn, thePid);
    IF NOT FOUND THEN
      return;
    END IF;

    --
    -- See if it is a PV
    --
    SELECT INTO thepvname,themotion kvpvname,kvmotion FROM px.kvs WHERE kvname = theObj and (kvpvname is not null or kvmotion is not null);
    IF FOUND THEN
      IF array_length( theParams, 1) = 1 THEN
          --
          -- Only call caput if we have exactly one value
          --
        SELECT INTO currentValue kvvalue FROM px.kvs WHERE kvpvname=thepvname and not kvro LIMIT 1;
        IF FOUND THEN 
          IF theCmd = 'moveRel' THEN
            --
            -- Safely assume that the current position and the requested change are both convertable to numeric types
            --
            arg1 := (currentValue::numeric + (theParams[1])::numeric)::text;
          ELSE
            arg1 := theParams[1];
          END IF;

          IF currentValue != arg1 THEN
            --
            -- The new value must be different.  This logic might get us into trouble if round off error is involved.
            --
            IF themotion is not null THEN
              SELECT INTO motionOK epics.moveit( themotion, arg1::numeric);
              --
              -- We should probably do something with motionOK.  It's false if epics.moveit refused to do a caput
              -- Errors get reported to the MD2 and should probably also get reported to the remote user (TODO)
              --
            ELSE
              PERFORM epics.caput( thepvname, arg1);
            END IF;
          END IF;
        END IF;      
       END IF;
    ELSE
      --
      -- See if it is a remote function call
      --
      PERFORM 1 FROM rmt.kvcmdparams WHERE kvcpcmd=theCmd and kvcpobj=theobj LIMIT 1;
      IF FOUND THEN
        FOR params IN SELECT * FROM rmt.kvcmdparams WHERE kvcpcmd=theCmd and kvcpobj=theobj ORDER BY kvcpindex LOOP
          IF array_length( theParams, 1) > params.kvcpindex THEN
            IF length(params.kvcpname)=0 THEN
              PERFORM px.kvset( -1, params.kvcpobj, theParams[params.kvcpindex + 1]);
            ELSE
              PERFORM px.kvset( -1, params.kvcpobj || '.' || params.kvcpname, theParams[params.kvcpindex + 1]);
            END IF;
          ELSE
            IF length(params.kvcpname)=0 THEN
              PERFORM px.kvset( -1, params.kvcpobj, params.kvcpdefault);
            ELSE
              PERFORM px.kvset( -1, params.kvcpobj || '.' || params.kvcpname, params.kvcpdefault);
            END IF;
          END IF;
        END LOOP;
        IF params.kvcpcmd != 'set_value' THEN
          EXECUTE 'select rmt.' || params.kvcpcmd || '(' || thestn || ',''' || thepid || ''',''' || params.kvcpobj || ''')';
        END IF;
      ELSE
        --
        -- Make up the string to send to the md2
        --
        md2String := theCmd || ' ' || substring( theObj from 8);

        IF array_length( theParams, 1) > 0 THEN
          md2String := md2String || ' ' || array_to_string( theParams, ' ');
        END IF;
        --
        -- Ready
        --
	-- raise notice 'motionRequest for md2: %', md2String;
        PERFORM px.md2pushqueue( theStn, md2String);
      END IF;
    END IF;

    --
    -- That's it
    --
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.motionRequest( text, text, text, text[]) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.setcenter( thestn int, thepid text, theobj text) returns void as $$
  DECLARE
    zoom int;
    dx float;
    dy float;
    dz float;
    b  float;
    t0 float;
  BEGIN
    SELECT INTO zoom kvvalue::int   FROM px.kvs WHERE kvname=theobj || '.zoom';
    SELECT INTO dx   kvvalue::float FROM px.kvs WHERE kvname=theobj || '.dx';
    SELECT INTO dy   kvvalue::float FROM px.kvs WHERE kvname=theobj || '.dy';
    SELECT INTO dz   kvvalue::float FROM px.kvs WHERE kvname=theobj || '.dz';
    SELECT INTO b    kvvalue::float FROM px.kvs WHERE kvname=theobj || '.b';
    SELECT INTO t0   kvvalue::float FROM px.kvs WHERE kvname=theobj || '.t0';
    PERFORM px.setcenter( thestn, thepid, '0.0.0.0'::inet, 0, zoom, dx, dy, dz, b, t0);
    PERFORM px.md2pushqueue( thestn, 'rotate');
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.setcenter( int, text, text) OWNER TO lsadmin;

CREATE OR REPLACE FUNCTION rmt.addcenter( thestn int, thepid text, theobj text) returns void as $$
  DECLARE
    from_index int;
    to_index int;
    from_base  text;
    to_base  text;
    centers_length int;
    thevalue  text;
    thekey    text;
  BEGIN
    centers_length = px.kvget( theobj || '.length')::int;
    centers_length = centers_length + 1;

    IF centers_length < 1 THEN
      centers_length := 1;
    END IF;
    PERFORM px.kvset( theobj || '.length', centers_length::text);

    from_index = px.kvget( theobj || '.editIndex')::int;
    to_index   = centers_length - 1;
    PERFORM px.kvset( theobj || '.editIndex', to_index::text);

    IF centers_length = 1 or from_index < 0 or from_index >= to_index THEN
      return;
    END IF;

    from_base := theobj || '.' || from_index;
    to_base   := theobj || '.' || to_index;

    FOR thekey, thevalue IN SELECT replace(kvname,from_base,to_base), kvvalue FROM px.kvs WHERE kvname like from_base || '.%' LOOP
      PERFORM px.kvset( thekey, thevalue);
    END LOOP;
    PERFORM px.kvset( theobj || '.zoom', coalesce(px.kvget( to_base || '.zoom'), '1'));
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.addcenter( int, text, text) OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.delcenter( thestn int, thepid text, theobj text) returns void as $$
  DECLARE
    del_index int;
    edit_index int;
    centers_length int;
    to_base text;
    from_base text;
    thekey text;
    thevalue text;
    thezoom text;
  BEGIN
    centers_length = px.kvget( theobj || '.length')::int;
    IF centers_length <= 1 THEN
      return;
    END IF;

    del_index      = (coalesce(px.kvget( theobj || '.delIndex'), '-1'))::int;
    IF del_index < 0 THEN
      del_index = centers_length + del_index;
    END IF;

    raise notice 'del_index: %', del_index;

    IF del_index < 0 or del_index >= centers_length THEN
      return;
    END IF;

    edit_index = (coalesce(px.kvget( theobj || '.editIndex'), '0'))::int;
    thezoom    = coalesce( px.kvget( theobj || '.' || edit_index || '.zoom'), '1');

    FOR i IN del_index .. (centers_length-2) LOOP
      to_base = theobj||i;
      from_base = theobj||(i+1);
      FOR thekey, thevalue IN SELECT replace( kvname, from_base, to_base), kvvalue FROM px.kvs WHERE kvname like from_base || '.%' LOOP
        PERFORM px.kvset( -1, thekey, thevalue);
      END LOOP;
    END LOOP;

    centers_length = centers_length - 1;
    PERFORM px.kvset( theobj || '.length', centers_length::text);

    if edit_index >= centers_length THEN
      edit_index = centers_length - 1;
      PERFORM px.kvset( theobj || '.editIndex', edit_index::text);
      PERFORM px.kvset( theobj || '.zoom', thezoom);
    END IF;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.delcenter( int, text, text) OWNER TO lsadmin;



CREATE OR REPLACE FUNCTION rmt.setkvs( thePid text, theks text[], thevs text[]) returns void as $$
  DECLARE
    thekey text;
    thevalue text;
    thestn int;
    theesaf int;
    cur record;
    maybelist text[];
    thekvkey int;
    theseq int;
  BEGIN
    PERFORM 1 WHERE rmt.checkpid( thepid);
    IF NOT FOUND THEN
      return;
    END IF;

    FOR i IN array_lower( theks, 1) .. array_upper( theks, 1) LOOP
      thekey   := theks[i];
      thevalue := thevs[i];
      maybelist :=  regexp_matches( thekey, E'^(stns|esafs)\.([0-9]+?)\.+(.+)+$')
      IF maybelist is not null THEN
        -- we have an array
        --
        IF maybelist[1] = '' THEN
          -- don't allow keys to start with a dot
          return;
        END IF;
        IF (lower(maybelist[1]) = 'stns' THEN
          thestn = (maybelist[2])::int;
          theesaf = NULL;
          PERFORM 1 FROM rmt.checkstnaccess( thestn, thepid);
	  IF NOT FOUND THEN
            RETURN;
          END IF;
        END IF;

        IF (lower(maybelist[1]) = 'esafs' THEN
          theesaf = (maybelist[2])::int;
          thestn = NULL;
          PERFORM 1 FROM rmt.checkesafaccess( theesaf, thepid);
	  IF NOT FOUND THEN
            RETURN;
          END IF;
        END IF;

        IF thestn is not null or theesaf is not null THEN

          SELECT INTO thekvkey kvkey FROM px.kvs WHERE kvname=thekey;
          IF thekvkey is not null THEN
            PERFORM 1 FROM px.kvs WHERE kvkey=thekvkey and kvvalue=thevalue;
	    IF FOUND THEN
              UPDATE px.kvs SET kvts=now() WHERE kvkey=thekvkey;
            ELSE
              IF theSeq is null THEN
                SELECT INTO theSeq nextval( 'px.kvs_kvseq_seq');
              END IF;
              UPDATE px.kvs SET kvts=now(), kvvalue=thevalue, kvseq=theseq WHERE kvkey=thekvkey;
            END IF;
          ELSE
            IF theSeq is null THEN
              SELECT INTO theSeq nextval( 'px.kvs_kvseq_seq');
            END IF;
            INSERT INTO px.kvs (kvts, kvseq, kvname, kvvalue) VALUES (now(), theseq, thekey, thevalue);
          END IF;
        END IF;
      ELSE
        --
        -- Not an array, not currently supported
        --
      END IF;
    END LOOP;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.setkvs( text, text[], text[]) OWNER TO lsadmin;


drop table if exists rmt._beamstatepvs cascade;
CREATE TABLE rmt._beamstatepvs (
       bsstn int primary key,
       kvbeamstate         int references px.kvs (kvkey),
       kvbeamreason        int references px.kvs (kvkey),
       kvbeamni0           int references px.kvs (kvkey),
       global_online       int references epics._pvmonitors (pvmmonitorindex),
       acis_permit         int references epics._pvmonitors (pvmmonitorindex),
       chain_a_major_fault int references epics._pvmonitors (pvmmonitorindex),
       chain_b_major_fault int references epics._pvmonitors (pvmmonitorindex),
       chain_c_major_fault int references epics._pvmonitors (pvmmonitorindex),
       chain_a_minor_fault int references epics._pvmonitors (pvmmonitorindex),
       chain_b_minor_fault int references epics._pvmonitors (pvmmonitorindex),
       chain_c_minor_fault int references epics._pvmonitors (pvmmonitorindex),
       di_water_fault      int references epics._pvmonitors (pvmmonitorindex),
       fe_eps              int references epics._pvmonitors (pvmmonitorindex),
       fes                 int references epics._pvmonitors (pvmmonitorindex),
       a_enabled           int references epics._pvmonitors (pvmmonitorindex),
       a_door_1_a          int references epics._pvmonitors (pvmmonitorindex),
       a_door_1_b          int references epics._pvmonitors (pvmmonitorindex),
       a_door_2_a          int references epics._pvmonitors (pvmmonitorindex), 
       a_door_2_b          int references epics._pvmonitors (pvmmonitorindex),
       a_user_key	   int references epics._pvmonitors (pvmmonitorindex),
       a_searching         int references epics._pvmonitors (pvmmonitorindex),
       a_searched          int references epics._pvmonitors (pvmmonitorindex),
       a_beam_active       int references epics._pvmonitors (pvmmonitorindex),
       b_enabled           int references epics._pvmonitors (pvmmonitorindex),
       b_door_1_a          int references epics._pvmonitors (pvmmonitorindex),
       b_door_1_b          int references epics._pvmonitors (pvmmonitorindex),
       b_door_2_a          int references epics._pvmonitors (pvmmonitorindex), 
       b_door_2_b          int references epics._pvmonitors (pvmmonitorindex),
       b_user_key	   int references epics._pvmonitors (pvmmonitorindex),
       b_searching         int references epics._pvmonitors (pvmmonitorindex),
       b_searched          int references epics._pvmonitors (pvmmonitorindex),
       b_beam_active       int references epics._pvmonitors (pvmmonitorindex),
       c_enabled           int references epics._pvmonitors (pvmmonitorindex),
       c_door_1_a          int references epics._pvmonitors (pvmmonitorindex),
       c_door_1_b          int references epics._pvmonitors (pvmmonitorindex),
       c_user_key	   int references epics._pvmonitors (pvmmonitorindex),
       c_searching         int references epics._pvmonitors (pvmmonitorindex),
       c_searched          int references epics._pvmonitors (pvmmonitorindex),
       c_beam_active       int references epics._pvmonitors (pvmmonitorindex),

       stn_shutter         int references epics._pvmonitors (pvmmonitorindex),
       stn_enabled         int references epics._pvmonitors (pvmmonitorindex),
       stn_door_p_a        int references epics._pvmonitors (pvmmonitorindex),
       stn_door_p_b        int references epics._pvmonitors (pvmmonitorindex),
       stn_door_m_a        int references epics._pvmonitors (pvmmonitorindex), 
       stn_door_m_b        int references epics._pvmonitors (pvmmonitorindex),
       stn_user_key        int references epics._pvmonitors (pvmmonitorindex),
       stn_searching       int references epics._pvmonitors (pvmmonitorindex),
       stn_searched        int references epics._pvmonitors (pvmmonitorindex),
       stn_beam_active     int references epics._pvmonitors (pvmmonitorindex)

);
ALTER TABLE rmt._beamstatepvs OWNER TO lsadmin;

INSERT INTO rmt._beamstatepvs (bsstn) values (1);
INSERT INTO rmt._beamstatepvs (bsstn) values (2);
INSERT INTO rmt._beamstatepvs (bsstn) values (3);
INSERT INTO rmt._beamstatepvs (bsstn) values (4);


UPDATE rmt._beamstatepvs SET global_online       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:ACIS_GLOBAL_ONLINE';
UPDATE rmt._beamstatepvs SET acis_permit         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:ACIS_FE_PERMIT';
UPDATE rmt._beamstatepvs SET chain_a_major_fault = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:ChainAMajorFault';
UPDATE rmt._beamstatepvs SET chain_b_major_fault = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:ChainBMajorFault';
UPDATE rmt._beamstatepvs SET chain_c_major_fault = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_FAULT_PRESENT_CC';
UPDATE rmt._beamstatepvs SET chain_a_minor_fault = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:ChainAMinorFault';
UPDATE rmt._beamstatepvs SET chain_b_minor_fault = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:ChainBMinorFault';
UPDATE rmt._beamstatepvs SET chain_c_minor_fault = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:ChainCMinorFault';
UPDATE rmt._beamstatepvs SET di_water_fault      = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PD:21ID:DIWalarm';
UPDATE rmt._beamstatepvs SET fe_eps              = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:IC_FEEPS_FE_PERMIT';
UPDATE rmt._beamstatepvs SET fes                 = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_A_SHUTTER_CLOSED';
UPDATE rmt._beamstatepvs SET a_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_A_APS_ENABLED';
UPDATE rmt._beamstatepvs SET a_door_1_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_A_DR1_CLOS';
UPDATE rmt._beamstatepvs SET a_door_1_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_A_DR1_CLOS';
UPDATE rmt._beamstatepvs SET a_door_2_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_A_DR2_CLOS';
UPDATE rmt._beamstatepvs SET a_door_2_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_A_DR2_CLOS';
UPDATE rmt._beamstatepvs SET a_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_A_USER_KEY';
UPDATE rmt._beamstatepvs SET a_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_A_VOICE_1';
UPDATE rmt._beamstatepvs SET a_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_A_SEARCHED';
UPDATE rmt._beamstatepvs SET a_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_A_BEAM_ACTIVE';
UPDATE rmt._beamstatepvs SET b_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_B_APS_ENABLED';
UPDATE rmt._beamstatepvs SET b_door_1_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_B_DR1_CLOS';
UPDATE rmt._beamstatepvs SET b_door_1_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_B_DR1_CLOS';
UPDATE rmt._beamstatepvs SET b_door_2_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_B_DR2_CLOS';
UPDATE rmt._beamstatepvs SET b_door_2_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_B_DR2_CLOS';
UPDATE rmt._beamstatepvs SET b_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_B_USER_KEY';
UPDATE rmt._beamstatepvs SET b_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_B_VOICE_1';
UPDATE rmt._beamstatepvs SET b_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_B_SEARCHED';
UPDATE rmt._beamstatepvs SET b_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_B_BEAM_ACTIVE';
UPDATE rmt._beamstatepvs SET c_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_C_APS_ENABLED';
UPDATE rmt._beamstatepvs SET c_door_1_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_BC_C_DR1_CLOS';
UPDATE rmt._beamstatepvs SET c_door_1_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_BC_C_DR1_CLOS';
UPDATE rmt._beamstatepvs SET c_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_C_USER_KEY';
UPDATE rmt._beamstatepvs SET c_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_BC_C_VOICE_1';
UPDATE rmt._beamstatepvs SET c_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_C_SEARCHED';
UPDATE rmt._beamstatepvs SET c_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_C_BEAM_ACTIVE';


UPDATE rmt._beamstatepvs SET kvbeamstate           = kvkey           FROM px.kvs            WHERE kvname ='stns.1.beam.state'            AND bsstn=1;
UPDATE rmt._beamstatepvs SET kvbeamreason          = kvkey           FROM px.kvs            WHERE kvname ='stns.1.beam.reason'           AND bsstn=1;
UPDATE rmt._beamstatepvs SET kvbeamni0             = kvkey           FROM px.kvs            WHERE kvname ='stns.1.beam.ni0'              AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_shutter           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_D_SHUTTER_CLOSED' AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_D_APS_ENABLED'    AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_door_m_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_D_DR1_CLOS'    AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_door_m_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_D_DR1_CLOS'    AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_door_p_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_D_DR2_CLOS'    AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_door_p_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_D_DR2_CLOS'    AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_D_USER_KEY'       AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_D_VOICE_1'     AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_D_SEARCHED'       AND bsstn=1;
UPDATE rmt._beamstatepvs SET stn_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_D_BEAM_ACTIVE'    AND bsstn=1;

UPDATE rmt._beamstatepvs SET kvbeamstate           = kvkey           FROM px.kvs            WHERE kvname ='stns.2.beam.state'              AND bsstn=2;
UPDATE rmt._beamstatepvs SET kvbeamreason          = kvkey           FROM px.kvs            WHERE kvname ='stns.2.beam.reason'             AND bsstn=2;
UPDATE rmt._beamstatepvs SET kvbeamni0             = kvkey           FROM px.kvs            WHERE kvname ='stns.2.beam.ni0'                AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_shutter           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_E_SHUTTER_CLOSED'   AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_E_APS_ENABLED'      AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_door_p_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_DE_E_DR1_CLOS'   AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_door_p_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_DE_E_DR1_CLOS'   AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_door_m_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_DE_E_DR2_CLOS'   AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_door_m_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_DE_E_DR2_CLOS'   AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_E_USER_KEY'         AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_DE_E_VOICE_1'    AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_E_SEARCHED'         AND bsstn=2;
UPDATE rmt._beamstatepvs SET stn_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_E_BEAM_ACTIVE'      AND bsstn=2;

UPDATE rmt._beamstatepvs SET kvbeamstate           = kvkey           FROM px.kvs            WHERE kvname ='stns.3.beam.state'              AND bsstn=3;
UPDATE rmt._beamstatepvs SET kvbeamreason          = kvkey           FROM px.kvs            WHERE kvname ='stns.3.beam.reason'             AND bsstn=3;
UPDATE rmt._beamstatepvs SET kvbeamni0             = kvkey           FROM px.kvs            WHERE kvname ='stns.3.beam.ni0'                AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_shutter           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_F_SHUTTER_CLOSED'   AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_F_APS_ENABLED'      AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_door_m_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_F_DR1_CLOS'      AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_door_m_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_F_DR1_CLOS'      AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_door_p_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_F_DR2_CLOS'      AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_door_p_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_F_DR2_CLOS'      AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_F_USER_KEY'         AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_F_VOICE_1'       AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_F_SEARCHED'         AND bsstn=3;
UPDATE rmt._beamstatepvs SET stn_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_F_BEAM_ACTIVE'      AND bsstn=3;

UPDATE rmt._beamstatepvs SET kvbeamstate           = kvkey           FROM px.kvs            WHERE kvname ='stns.4.beam.state'              AND bsstn=4;
UPDATE rmt._beamstatepvs SET kvbeamreason          = kvkey           FROM px.kvs            WHERE kvname ='stns.4.beam.reason'             AND bsstn=4;
UPDATE rmt._beamstatepvs SET kvbeamni0             = kvkey           FROM px.kvs            WHERE kvname ='stns.4.beam.ni0'                AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_shutter           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_G_SHUTTER_CLOSED'   AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_enabled           = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_G_APS_ENABLED'      AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_door_p_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_FG_G_DR1_CLOS'   AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_door_p_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_FG_G_DR1_CLOS'   AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_door_m_a          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:IA_STA_FG_G_DR2_CLOS'   AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_door_m_b          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PB:21ID:IB_STA_FG_G_DR2_CLOS'   AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_user_key          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_G_USER_KEY'         AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_searching         = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PA:21ID:OA_STA_FG_G_VOICE_1'    AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_searched          = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_G_SEARCHED'         AND bsstn=4;
UPDATE rmt._beamstatepvs SET stn_beam_active       = pvmmonitorindex FROM epics._pvmonitors WHERE pvmname='PC:21ID:STA_G_BEAM_ACTIVE'      AND bsstn=4;


drop view if exists rmt.beamstatepvs;
CREATE VIEW rmt.beamstatepvs (stn, kvbeamstate, kvbeamreason, kvbeamni0, global_online, acis_permit, chain_a_major_fault, chain_b_major_fault, chain_c_major_fault,
                              chain_a_minor_fault, chain_b_minor_fault, chain_c_minor_fault, diwater_fault, fe_eps, fes,
                              a_enabled, a_door_1_a, a_door_1_b, a_door_2_a, a_door_2_b, a_user_key, a_searching, a_searched, a_beam_active,
                              b_enabled, b_door_1_a, b_door_1_b, b_door_2_a, b_door_2_b, b_user_key, b_searching, b_searched, b_beam_active,
                              c_enabled, c_door_1_a, c_door_1_b, c_user_key, c_searching, c_searched, c_beam_active,
                              stn_shutter, stn_enabled, stn_door_p_a, stn_door_p_b, stn_door_m_a, stn_door_m_b, stn_user_key, stn_searching, stn_searched, stn_beam_active
                              ) AS
SELECT bsstn, kvbeamstate, kvbeamreason, kvbeamni0,
       epics._caget( global_online), epics._caget( acis_permit), epics._caget( chain_a_major_fault), epics._caget( chain_b_major_fault), epics._caget( chain_c_major_fault),
       epics._caget( chain_a_minor_fault), epics._caget( chain_b_minor_fault), epics._caget( chain_c_minor_fault), epics._caget( di_water_fault), epics._caget( fe_eps), epics._caget( fes),
       epics._caget( a_enabled), epics._caget( a_door_1_a), epics._caget( a_door_1_b), epics._caget( a_door_2_a), epics._caget( a_door_2_b),
       epics._caget( a_user_key), epics._caget( a_searching), epics._caget(a_searched), epics._caget(a_beam_active),
       epics._caget( b_enabled), epics._caget( b_door_1_a), epics._caget( b_door_1_b), epics._caget( b_door_2_a), epics._caget( b_door_2_b),
       epics._caget( b_user_key), epics._caget( b_searching), epics._caget(b_searched), epics._caget(b_beam_active),
       epics._caget( c_enabled), epics._caget( c_door_1_a), epics._caget( c_door_1_b),
       epics._caget( c_user_key), epics._caget( c_searching), epics._caget(c_searched), epics._caget(c_beam_active),
       epics._caget( stn_shutter), epics._caget( stn_enabled), epics._caget( stn_door_p_a), epics._caget( stn_door_p_b), epics._caget( stn_door_m_a), epics._caget( stn_door_m_b),
       epics._caget( stn_user_key), epics._caget( stn_searching), epics._caget(stn_searched), epics._caget(stn_beam_active)

 FROM rmt._beamstatepvs;
ALTER VIEW rmt.beamstatepvs OWNER TO lsadmin;


CREATE OR REPLACE FUNCTION rmt.beamstate( thestn int) returns TEXT as $$
  DECLARE
    rtn text;
    bs record;
    ba boolean;
    thestatek int;
    thestate text;
    thereasonk int;
    thereason text;
    theni0k int;
    theni0 text;
    ni0 text;
    theSeq int;
  BEGIN
    ni0 := px.rt_get_ni0(theStn);
    SELECT INTO ba, thestatek, thereasonk, theni0k, rtn 
      stn_beam_active::int = 1, kvbeamstate, kvbeamreason, kvbeamni0,
      CASE
      WHEN stn_beam_active::int = 1 THEN ni0
      WHEN fes::int = 1 THEN CASE
        WHEN global_online::int = 0 THEN 'PSS Offline'
        WHEN acis_permit::int   = 0 THEN 'ACIS Permit Needed'
        WHEN floor(chain_a_major_fault::float)::int != 0 or floor(chain_b_major_fault::float)::int != 0 or floor(chain_c_major_fault::float)::int != 0 THEN 'PSS Major Fault'
        WHEN floor(chain_a_minor_fault::float)::int != 0 or floor(chain_b_minor_fault::float)::int != 0 or floor(chain_c_minor_fault::float)::int != 0 THEN 'PSS Minor Fault'
        WHEN floor(diwater_fault::float)::int != 0 THEN 'DI Water Fault'
        WHEN fe_eps::int != 1 THEN 'FE-EPS Fault'
        WHEN a_searching::int = 1 THEN 'Searching Station A'
        WHEN a_enabled::int   = 0 THEN 'Station A Not Enabled by APS'
        WHEN a_user_key::int  = 0 THEN 'Station A User Key Missing'
        WHEN a_door_1_a::int = 0 or a_door_1_b::int = 0 THEN 'Station A Manual Door Open'
        WHEN a_door_2_a::int = 0 or a_door_2_b::int = 0 THEN 'Station A Pneumatic Door Open'
        WHEN a_searched::int = 0 THEN 'Station A Search Needed'
        WHEN b_searching::int = 1 THEN 'Searching Station B'
        WHEN b_enabled::int   = 0 THEN 'Station B Not Enabled by APS'
        WHEN b_user_key::int  = 0 THEN 'Station B User Key Missing'
        WHEN b_door_1_a::int = 0 or b_door_1_b::int = 0 THEN 'Station B Manual Door Open'
        WHEN b_door_2_a::int = 0 or b_door_2_b::int = 0 THEN 'Station B Pneumatic Door Open'
        WHEN b_searched::int = 0 THEN 'Station B Search Needed'
        WHEN c_searching::int = 1 THEN 'Searching Station C'
        WHEN c_enabled::int   = 0 THEN 'Station C Not Enabled by APS'
        WHEN c_user_key::int  = 0 THEN 'Station C User Key Missing'
        WHEN c_door_1_a::int = 0 or c_door_1_b::int = 0 THEN 'Station C Door Open'
        WHEN c_searched::int = 0 THEN 'Station C Search Needed'
        ELSE 'Front End Shutter Closed'
        END
      WHEN stn_shutter::int     = 1 THEN CASE
        WHEN stn_searching::int = 1 THEN 'Searching Station'
        WHEN stn_enabled::int   = 0 THEN 'Station Not Enabled by APS'
        WHEN stn_user_key::int  = 0 THEN 'Station User Key Missing'
        WHEN stn_door_m_a::int = 0 or stn_door_m_b::int = 0 THEN 'Station Manual Door Open'
        WHEN stn_door_p_a::int = 0 or stn_door_p_b::int = 0 THEN 'Station Pneumatic Door Open'
        WHEN stn_searched::int = 0 THEN 'Search Needed'
        ELSE 'Station Shutter Closed'
        END
      ELSE 'Beam Off'
      END
    FROM rmt.beamstatepvs WHERE stn=thestn;

    SELECT INTO thestate  coalesce(kvvalue,'-1') FROM px.kvs WHERE kvkey=thestatek;
    SELECT INTO thereason coalesce(kvvalue,'') FROM px.kvs WHERE kvkey=thereasonk;
    SELECT INTO theni0    coalesce(kvvalue,'--') FROM px.kvs WHERE kvkey=theni0k;
    theseq := NULL;

    IF ba THEN
      -- Got beam
      --
      IF thestate::int != 3 THEN
        -- But we didn't last time
        --
        SELECT INTO theSeq nextval( 'px.kvs_kvseq_seq');
        UPDATE px.kvs SET kvvalue='3',  kvseq=theSeq, kvts = now() WHERE kvkey=thestatek;
        UPDATE px.kvs SET kvvalue=rtn,   kvseq=theSeq, kvts = now() WHERE kvkey=thereasonk;
        UPDATE px.kvs SET kvvalue='--', kvseq=theSeq, kvts = now() WHERE kvkey=theni0k;
      ELSE
        --
        --
        IF theni0 != ni0 THEN
          SELECT INTO theSeq nextval( 'px.kvs_kvseq_seq');
          UPDATE px.kvs SET kvvalue=ni0, kvseq=theSeq, kvts = now() WHERE kvkey=theni0k;
          UPDATE px.kvs SET kvvalue='',  kvseq=theSeq, kvts = now() WHERE kvkey=thereasonk and thereason != '';
        END IF;
      END IF;
    ELSE
      -- No beam
      --
      IF thestate::int = 3 THEN
        -- And we did last time
        --
        SELECT INTO theSeq nextval( 'px.kvs_kvseq_seq');
        UPDATE px.kvs SET kvvalue=rtn,  kvseq=theSeq, kvts = now() WHERE kvkey=thereasonk;
        UPDATE px.kvs SET kvvalue='--', kvseq=theSeq, kvts = now() WHERE kvkey=theni0k;
      ELSE
        --
        IF thereason != rtn THEN
          SELECT INTO theSeq nextval( 'px.kvs_kvseq_seq');
          UPDATE px.kvs SET kvvalue=rtn,  kvseq=theSeq, kvts = now() WHERE kvkey=thereasonk;
        END IF;
      END IF;
      IF theSeq is not NULL THEN
        IF rtn = 'Front End Shutter Closed' THEN
          UPDATE px.kvs SET kvvalue='1',  kvseq=theSeq, kvts = now() WHERE kvkey=thestatek;
        ELSIF rtn = 'Station Shutter Closed' THEN
          UPDATE px.kvs SET kvvalue='2',  kvseq=theSeq, kvts = now() WHERE kvkey=thestatek;
        ELSE
          UPDATE px.kvs SET kvvalue='0',  kvseq=theSeq, kvts = now() WHERE kvkey=thestatek;
        END IF;
      END IF;
    END IF;

    return rtn;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
ALTER FUNCTION rmt.beamstate( int) OWNER TO lsadmin;


CREATE TABLE rmt.webpreparedstatements (wpskey serial primary key, wpsname text unique, wpsquery text);
ALTER TABLE rmt.webpreparedstatements OWNER TO lsadmin;

INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getpid (text,text)', 'select rmt.getpid( $1, $2) as pid');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('checkpid (text)', 'select rmt.checkpid($1) as tf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('newrole (text,text)', 'select rmt.newrole( $1, $2) as nr');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getlivevarlistrw (text)', 'select rmt.getLiveVarListRW( $1) as v');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getrole (text)     ', 'select rmt.getrole( $1) as therole');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getesafs (text)    ', 'select budirectory, esafexpid, homedirectory, eidstartdate::date as  sd FROM rmt.getEsafs( $1) left join esaf.esafs on eexperimentid::int=esafexpid::int');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('cmdrqststart (text,xml)', 'select rmt.cmdRqstStart( $1, $2) as r');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('uisinit (text)             ', 'select rmt.uisinit( $1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('uistreamget (text)', 'select uisk, uisv, uisseq from rmt.uistreamget($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('uisreinit (text,text)', 'select rmt.uisreinit( $1, $2)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('motionrequest (text,text,text,text[])', 'select rmt.motionRequest( $1, $2, $3, $4)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('logout (text)', 'select rmt.logout( $1) as u');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('setlivevars (text,text,text)', 'select rmt.setLiveVars( $1, $2, $3)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getshotsxml (text,text)', 'select px.getshotsxml( $1, $2) as rslt');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('cmdrqststatus (text,text)', 'select rmt.cmdRqstStatus( $1, $2) as crs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('cmdrqststatuslist (text, int, text, text)', 'select rmt.cmdRqstStatusList( $1, $2, $3, $4) as crs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('cmdrqstaction (text,text,text)', 'select rmt.cmdRqstAction( $1, $2, $3) as crs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('setmailinform (text,xml)', 'select rmt.setmailinform( $1, $2) as mif');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('changeuserfeed (text,text)', 'select rmt.changeuserfeed( $1, $2)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('feedlistxml (text)', 'select rmt.feedlistxml($1) as flx');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('startuserfeed (text,inet,int,text)', 'select rmt.startUserFeed( $1, $2, $3, $4)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getcenteringvideoxml (text,int)', 'select rmt.getcenteringvideosxml( $1, $2) as gcv');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('requesthashvideo (text,inet,int,text)','select rmt.requesthashvideo( $1, $2, $3, $4)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('setcenter (int,text,inet,int,int,float,float,float,float,float)', 'select px.setcenter($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('md2pushqueue( int,text)', 'select px.md2pushqueue($1,$2)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('stnstatusxmlesaf (int)', 'select px.stnstatusxml($1) as ssx');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('stnstatusxml     (text)', 'select px.stnstatusxml($1) as ssx');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('setdiffmode (text,int,text)', 'select rmt.setdiffmode( $1, $2, $3) as rsp');

INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('xmlprefixsearch (int, text)', 'select rmt.xmlprefixsearch( $1, $2) as xs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('xmldspidnhpid (text)', 'select rmt.xmldspidnh( $1) as xd');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('xmldspidnhskey (int)', 'select rmt.xmldspidnh( sdspid) as xd FROM px.shots WHERE skey=$1');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('xmlsubdirnh (int,text)', 'select rmt.xmlsubdirsnh( $1, $2) as xd');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('xmlesafnh (text)', 'select rmt.xmlesafnh($1) as xe');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getrobotstatexml( text, int)', 'select cats.getrobotstatexml( $1, $2) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('isrqstjpeg (text,int,text,text,int,int,int,int,int,int,int,int)', 'select rmt.isrqstjpeg($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) as hs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('isrqstprofile (text,int,text,text,int,int,int,int,int)', 'select rmt.isrqstprofile($1,$2,$3,$4,$5,$6,$7,$8,$9) as hs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('isrqstheader (text,int,text,text)', 'select rmt.isrqstheader($1,$2,$3,$4) as hs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('isrqstindexing (text,int,text,int,int)', 'select rmt.isrqstindexing($1,$2,$3,$4,$5) as hs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('isrqstdownload (text,int,text,int)', 'select rmt.isrqstdownload($1,$2,$3,$4) as hs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('isrqsttarball (text,int,text,text)', 'select rmt.isrqsttarball($1,$2,$3,$4) as hs');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('openlid1 (int)', 'select cats.openlid1($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('closelid1 (int)', 'select cats.closelid1($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('openlid2 (int)', 'select cats.openlid2($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('closelid2 (int)', 'select cats.closelid2($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('openlid3 (int)', 'select cats.openlid3($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('closelid3 (int)', 'select cats.closelid3($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('panic (int)', 'select cats.panic($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('abort (int)', 'select cats.abort($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('safe (int)', 'select cats.safe($1,0)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('back (int)', 'select cats.back($1,0)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('opentool (int)', 'select cats.opentool($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('closetool (int)', 'select cats.closetool($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('magneton (int)', 'select cats.magneton($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('magnetoff (int)', 'select cats.magnetoff($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('regulon (int)', 'select cats.regulon($1)');

INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('reguloff (int)', 'select cats.reguloff($1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('dry (int)', 'select cats.dry($1,0)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('soak (int)', 'select cats.soak($1,0)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('requestTransfer (int,int)', 'select px.requestTransfer( $1, $2)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('setBarCode (int,text,text)', 'select px.insertPuck( 0, $1, $2, $3, $3, TRUE)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getconfigfile (text, int)', 'select px.getconfigfile( $1, $2) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getallpuckpositionsxml (text, int)', 'select px.getallpuckpositionsxml( $1, $2) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('dfplist (text, int)', 'select px.dfplist( $1, $2) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('uistatus_set (text, int, text, text)', 'select px.uistatus_set( $1, $2, $3, $4)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('getds (text, text)', 'select px.getds( $1, $2) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('editds (text, int, text, text)', 'select px.editds( $1, $2, $3, $4) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('runds (text, int, text)', 'select px.runds( $1, $2, $3) as cf');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('pauserequest (int)', 'select px.pauserequest( $1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('unpause (int)', 'select px.unpause( $1)');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('checkstnaccess (int, text)', 'select rmt.checkstnaccess( $1, $2) as csa');
INSERT INTO rmt.webpreparedstatements (wpsname,wpsquery) VALUES ('pusherror (int, int, text)', 'select px.pusherror( $1, $2, $3)');

CREATE OR REPLACE FUNCTION rmt.webinit() returns void as $$
  DECLARE
    psn text;
    psq text;
  BEGIN
    FOR psn, psq IN SELECT wpsname, wpsquery FROM rmt.webpreparedstatements LOOP
      EXECUTE 'PREPARE ' || psn || ' as ' || psq;
    END LOOP;
    return;
  END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
