#!/usr/bin/bash
current_time=$(date +%H:%M)
current_date=$(date +%m%d%y)

# base directory path of where AMON-SENSS is located
dir_path="/home/$(whoami)/AMON-SENSS"

# generates AMON-SENSS application logs
log_file="${dir_path}/amon-logs/amon-startup_${current_date}.log"

log_json() {
    message=$1
    level=$2
    output=$3
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "{\"timestamp\": \"${timestamp}\", \"level\": \"${level}\", \"output\": \"${output}\", \"message\": \"${message}\"}" >> $log_file
}

exec 2> >(while read line; do log_json "$line" "ERROR" "stderr"; done)

kill_process() {
    local process_name=$1
    local pid=$(ps -ef | grep "$process_name" | grep -vE 'grep|vim|bash' | awk '{print $2}')
    if [ -n "$pid" ]; then
        log_json "Killing ${process_name} with PID ${pid}" "INFO" "stdout"
        kill -9 "$pid"
    else
        log_json "No ${process_name} process running." "INFO" "stdout"
    fi
}

start_DDOS() {
    log_json "Starting DDOS tasks at ${current_time}" "INFO" "stdout"

    kill_process "amonsenss"
    kill_process "/usr/bin/perl ${dir_path}/sum_alerts"
    kill_process "${dir_path}/env/bin/python3 ${dir_path}/ddosNotify.py"

    # Start new processes
    (
        cd $dir_path || exit
        today=$(date +%Y)/$(date +%m)/$(date +%d)
    # application logs
        nohup ./amonsenss -r ~/data -F nf -f > ~/AMON-SENSS/amon-logs/amon${current_date}.log 2>&1 &
    )
    # ddos alerts logs
    nohup /usr/bin/perl ${dir_path}/sum_alerts ${dir_path}/alerts.txt > ${dir_path}/ddos-logs/ddosAlert/ddosalert${current_date}.log 2>&1 &
    sleep 2

    log_json "DDOS tasks started successfully." "INFO" "stdout"
}

start_DDOS
