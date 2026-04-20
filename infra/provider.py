NETWORK_XML = """
<network>
  <name>forensics-isolated</name>
  <bridge name="virbr-forensics" stp="on" delay="0"/>
  <ip address="192.168.100.1" netmask="255.255.255.0">
    <dhcp>
      <range start="192.168.100.10" end="192.168.100.50"/>
    </dhcp>
  </ip>
</network>
"""

POOL_XML = """
<pool type="dir">
  <name>thesis-lab-pool</name>
  <target>
    <path>/srv/thesis-lab/disks</path>
  </target>
</pool>
"""