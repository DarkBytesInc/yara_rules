rule Win_Trojan_Pakes_975
{
strings:
	$a0 = { 550e032f94de77463ba5198280ccb0421ea10c0f217050bce08e6a0083d3eb597df95d75010be19bec77f6cda4c1f4742107de805f83700dc0c971e70031c3609b81ccb3b03b09c8240ac70197fe390c1dfe42bcc724c4be60b62367003de60da605125c2200f92e4f107f42ecda05b9d5cca64883f04cdd808c16b5d3484d440053623fd45a695200a6400c }

condition:
	$a0
}

        