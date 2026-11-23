start_file_monitor_service() {
  # 服务输出只保留本次启动；事件数据库在 logs/monitor 下按保留期单独清理
  (
    umask 077
    export CLASSPATH="$MODDIR/monitor.dex"
    exec /system/bin/app_process /system/bin org.srx.monitor.MonitorServer "$MODDIR"
  ) >"$LOGS_DIR/monitor-service.log" 2>&1 &
}
