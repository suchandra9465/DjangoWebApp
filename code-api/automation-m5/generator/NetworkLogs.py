import builtins as __builtin__
import sys
import re


class NetworkLogs:

    def __init__(self, options):
        self.options = options

    def chunk(self, *msg):
        return "\r\n%X\r\n%s" % (len(*msg), *msg)

    def print(self, *args, **kwargs):
        """My custom print() function."""
        # Adding new arguments to the print function signature
        if not self.options.web:
            __builtin__.print(*args, **kwargs)
        else:
            sys.stdout.write(self.chunk(str(*args).rstrip('\r') + "\r\n"))
        return

    def log(self, *args, level=5, **kwargs):
        if self.options.logging >= level:
            self.print(*args, **kwargs)
        return

    def log_info(self, *args, level=6, **kwargs):
        if self.options.logging >= level:
            self.print(*args, **kwargs)
        return

    def debug(self, *args, **kwargs):
        if self.options.logging >= 7:
            self.print('DEBUG:', *args, **kwargs)
        return

    def create_logging(self, customops):

        self.log(
            '''      <shared>
                    <log-settings>
                      <syslog>''')
        for log_profile in customops.logsettings:

            self.log('''            <entry name=\"''' + log_profile + '''\">''')
            self.log('''              <server>''')

            for log_server in customops.logsettings[log_profile]:
                self.log('''                <entry name=\"''' + log_server + '''\">
                      <transport>''' + customops.logsettings[log_profile][log_server]['transport'] + '''</transport>
                      <port>''' + customops.logsettings[log_profile][log_server]['port'] + '''</port>
                      <format>''' + customops.logsettings[log_profile][log_server]['format'] + '''</format>
                      <server>''' + customops.logsettings[log_profile][log_server]['server'] + '''</server>
                      <facility>''' + customops.logsettings[log_profile][log_server]['facility'] + '''</facility>
                    </entry>''')

            self.log('''              </server>
                </entry>''')

        self.log('''          </syslog>
              <config>
                <any>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                  <send-to-panorama>yes</send-to-panorama>
                  <send-snmptrap>
                    <using-snmptrap-setting>''' + customops.snmp_traps + '''</using-snmptrap-setting>
                  </send-snmptrap>
                </any>
              </config>

              <snmptrap>''')
        for snmp_profile in customops.trapprofiles:

            self.log('''            <entry name="''' + customops.snmp_traps + '''">
                  <version>
                    <v2c>
                      <server>''')
            for snmp_destination in customops.trapprofiles[snmp_profile]:
                self.log('''                    <entry name="''' + snmp_destination + '''">
                          <manager>''' + customops.trapprofiles[snmp_profile][snmp_destination]['ip'] + '''</manager>
                          <community>''' + customops.trapprofiles[snmp_profile][snmp_destination]['community'] + '''</community>
                        </entry>''')
            self.log('''                  </server>
                    </v2c>
                  </version>
                </entry>''')

        self.log('''          </snmptrap>
              <system>
                <informational>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                  <send-to-panorama>yes</send-to-panorama>
                  <send-snmptrap>
                    <using-snmptrap-setting>''' + customops.snmp_traps + '''</using-snmptrap-setting>
                  </send-snmptrap>
                </informational>
                <critical>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                  <send-to-panorama>yes</send-to-panorama>
                  <send-snmptrap>
                    <using-snmptrap-setting>''' + customops.snmp_traps + '''</using-snmptrap-setting>
                  </send-snmptrap>
                </critical>
                <high>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                  <send-to-panorama>yes</send-to-panorama>
                  <send-snmptrap>
                    <using-snmptrap-setting>''' + customops.snmp_traps + '''</using-snmptrap-setting>
                  </send-snmptrap>
                </high>
                <medium>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                  <send-to-panorama>yes</send-to-panorama>
                  <send-snmptrap>
                    <using-snmptrap-setting>''' + customops.snmp_traps + '''</using-snmptrap-setting>
                  </send-snmptrap>
                </medium>
                <low>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                  <send-to-panorama>yes</send-to-panorama>
                  <send-snmptrap>
                    <using-snmptrap-setting>''' + customops.snmp_traps + '''</using-snmptrap-setting>
                  </send-snmptrap>
                </low>
              </system>
              <correlation>
                <critical>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                </critical>
                <high>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                </high>
                <medium>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                </medium>
                <low>
                  <send-syslog>
                    <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                  </send-syslog>
                </low>
              </correlation>
            </log-settings>
          </shared>
          <pan7>
            <log-settings>
              <profiles>
                <entry name=\"''' + customops.log_forward_profile_name + '''\">
                  <traffic>
                    <any>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </any>
                  </traffic>
                  <alarm>
                    <informational>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </informational>
                    <low>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </low>
                    <medium>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </medium>
                    <high>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </high>
                    <critical>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </critical>
                  </alarm>
                  <wildfire>
                    <benign>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </benign>
                    <grayware>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </grayware>
                    <malicious>
                      <send-to-panorama>yes</send-to-panorama>
                      <send-syslog>
                        <using-syslog-setting>''' + customops.logging + '''</using-syslog-setting>
                      </send-syslog>
                    </malicious>
                  </wildfire>
                </entry>
              </profiles>
            </log-settings>
          </pan7>
          <pan8>
            <log-settings>
              <profiles>
                <entry name=\"''' + customops.log_forward_profile_name + '''\">
                  <match-list>
                    <entry name=\"Matchlist\">
                      <send-syslog>
                        <member>AMER-Dell-Standard-Logging</member>
                      </send-syslog>
                      <log-type>traffic</log-type>
                      <filter>All Logs</filter>
                      <send-to-panorama>no</send-to-panorama>
                    </entry>
                  </match-list>
                </entry>
              </profiles>
            </log-settings>
          </pan8>''')
        return

    def sc(self, instr):

        outstr = re.sub('%20', ' ', instr)
        outstr = re.sub('%2b', '_', outstr)
        outstr = re.sub(r'[]`\/,?!@#$%^&*()<>;:=+{}\\\[\"\\\']', '_', outstr)
        return outstr

    def ss(self, instr):

        outstr = re.sub('%20', ' ', instr)
        outstr = re.sub('%2b', '_', outstr)

        return outstr
