#!/bin/sh
#
# audit_report.sh
#
# Create audit reports from Linux audit records
#

scriptname=`basename $0 .sh`
date=`date +"%Y-%m-%d"`
osname="`uname -s`"
hostname="`hostname | cut -d. -f1`"

# Define the audit logfile location
logfile=/var/log/remote/Linux_test.log

# Default time period for audit records
period="this-week"

# Centralized audit server
auditsrv="auditsrv1"


# Verify the OS
if [ "$osname" != "Linux" ]; then
	echo ""
	echo "This script only runs on Linux, not ${osname} !!"
	echo ""
	exit 1
fi

# Determine if running this script on the centralized audit server or an individual client
if [ "$hostname" = "$auditsrv" ]; then
	# Location of the centralized audit log on the audit server
	logfile=/var/log/remote/Linux_test.log
	logstring="-if ${logfile} "
else
	# Default location of the local Linux audit log
	logfile=/var/log/audit/audit.log
	logstring="--input-logs"
fi

# Validate that the audit file is readable and aureport/ausearch exist
if [ ! -x /usr/sbin/aureport ]; then
	echo "/usr/sbin/aureport does not exist"
	exit 1
fi
if [ ! -x /usr/sbin/ausearch ]; then
	echo "/usr/sbin/ausearch does not exist"
	exit 1
fi
if [ ! -r $logfile ]; then
	echo "$logfile does not exist"
	exit 1
fi



######################################################################
# Functions
# NOTE: Function names should be prefaced with an underscore (_)
######################################################################
_Blank() { echo "" ; }

_Pause() {
	echo '[42m[1mPress Return to Continue[0m'
	read ENT
}

_BlankPause() {
	echo '[42m[1mPress Return to Continue[0m'
	read ENT
	echo ""
}

_Usage() {
	_Blank
	echo "Usage:  ${scriptname} [ -a -h -l -p -t -v -w ]"
	echo "        -a           Run all reports"
	echo "        -h           Display usage"
	echo "        -l           Login/Auth report"
	echo "        -p           Privileged access report"
	echo "        -t           Testing mode"
	echo "        -v           Verbose output"
	echo "        -w           Watchdog report"
	_Blank
}

_MainMenu() {
	# Script main menu
	echo ""
	echo '------------------------------'
	echo "    Audit Report Main Menu    "
	echo '------------------------------'
	echo ""
	echo "  Report period: ${period}"
	echo ""
	echo "  1. Run all reports"
	echo "  2. Logon failures"
	echo "  3. Authentication report"
	echo "  4. Privileged report"
	echo "  5. File failures"
	echo "  6. Watchdog events"
	echo "  9. Audit period selection"
	echo "  0. Exit"
	echo ""
	echo "Enter number"
	read input
	
	case $input in
		1) _ReportAll ;;
		2) _ReportLogonFailures ;;
		3) _ReportAuth ;;
		4) _ReportPriv ;;
		5) _ReportFileFailures ;;
		6) _ReportWatchdog ;;
		9)	pinput=9
			while [ "$pinput" != "0" ]; do
				_PeriodSelectMenu
			done
			;;
		0) echo "" ;;
		*) echo "Invalid selection" ;;
	esac
}

_PeriodSelectMenu() {
	echo ""
	echo '------------------------------'
	echo "    Period Selection Menu    "
	echo '------------------------------'
	echo ""
	echo "  Current period: ${period}"
	echo ""
	echo "  1. today"
	echo "  2. this-week"
	echo "  3. this-month"
	echo "  4. this-year"
	echo "  0. Return to Main Menu"
	echo ""
	echo "Enter number"
	read pinput
	
	case $pinput in
		1) period="today" ;;
		2) period="this-week" ;;
		3) period="this-month" ;;
		4) period="this-year" ;;
		0) echo "" ;;
		*) echo "Invalid selection" ;;
	esac
}

_ReportAll() {
	_ReportSummary
	_ReportLogonFailures
	_ReportAuth
	_ReportFileFailures
	_ReportPriv
	_ReportAccountMods
	_ReportMAC
	_ReportSyscallFailures
	_ReportWatchdog
}

_ReportSummary() {
	# Summary report
	aureport ${logstring} --start ${period} --summary
	_BlankPause
}

_ReportLogonFailures() {
	# Failed logon report
	#
	# aureport example:
	# 17. 02/13/17 11:20:30 (unknown) 172.23.72.114 ssh /usr/sbin/sshd no 609075
	#
	# ausearch example:
	# node=sdc-linuxgw1.syr.lmco.com type=USER_LOGIN msg=audit(02/13/17 11:20:30.982:609075) : pid=27913 uid=root auid=unset ses=unset msg='op=login acct=(unknown) exe=/usr/sbin/sshd hostname=? addr=172.23.72.114 terminal=ssh res=failed'
	#
	aureport ${logstring} --start ${period} -l --failed
	_Blank
	ausearch ${logstring} --start ${period} -m LOGIN,USER_LOGIN --success no --interpret
	_BlankPause
}

_ReportAuth() {
	# Authentication report
	aureport ${logstring} --start ${period} -au
	_BlankPause
}

_ReportFileFailures() {
	# File access failures
	aureport ${logstring} --start ${period} -f --failed
	_BlankPause
}

_ReportPriv() {
	# Privileged report
	_Blank
	echo "Privileged access report"
	echo '==================================='
	ausearch ${logstring} --start ${period} -m ADD_USER,DEL_USER,ADD_GROUP,USER_CHAUTHTOK,DEL_GROUP,CHGRP_ID,ROLE_ASSIGN,ROLE_REMOVE -i
	_BlankPause
}

_ReportAccountMods() {
	# Account modifications
	aureport ${logstring} --start ${period} -m
	_BlankPause
}

_ReportMAC() {
	# Mandatory Access Control events
	aureport ${logstring} --start ${period} --mac
	_BlankPause
}

_ReportSyscallFailures() {
	# Failed system calls
	_Blank
	echo "Failed system calls"
	echo '==================================='
	ausearch ${logstring} --start ${period} -m SYSCALL -sv no -i
	_BlankPause
}

_ReportWatchdog() {
	# Watchdog events
	_Blank
	echo "Watchdog Events"
	echo '==================================='
	#ausearch ${logstring} --start ${period} -k watchdog
	ausearch ${logstring} --start ${period} -f /etc/watchdog
	_BlankPause
}



######################################################################
# Get input arguments
######################################################################
# -c <filename>     Output CSV file
# -d <delimiter>    Specify delimiter between fields in the check file
# -f <filename>     Specify input check file to use
# -h                Display Usage
# -m                Attempt to automatically remediate system
# -o                Output HTML Files
# -t                Testing mode
# -v                Verbose mode
# -?                Display Usage
while getopts "ahlptvw" opt; do
	case $opt in
		h) 
			_Usage
			;;
		a) 
			_ReportSummary
			_ReportLogonFailures
			_ReportAuth
			_ReportFileFailures
			_ReportPriv
			_ReportAccountMods
			_ReportMAC
			_ReportSyscallFailures
			_ReportWatchdog
			;;
		l) 
			_ReportLogonFailures
			_ReportAuth
			;;
		p) 
			_ReportPriv
			;;
		w) 
			_ReportWatchdog
			;;
		t) TESTING="Yes" ;;
		v) VERBOSE="Yes" ;;
		\?) echo "Invalid option: -$OPTARG" >&2
			_Usage
			exit 1 ;;
		:) echo "Option -$OPTARG requires an argument"
			_Usage
			exit 1 ;;
	esac
done


######################################################################
# Display the main menu
######################################################################
#while true; do
while [ "$input" != "0" ]; do
	_MainMenu
done

