rule Win_Trojan_Obfus_51
{
strings:
	$a0 = { 0e000001d03155a02995c8feffffff8500ffffff018550ffffff0145b44a8b9534fdffff09d083e86d138510ffffff23858cfdffff8995dcfdffff11956cfdffff218504feffff8b8538feffff3195f8fdffffff8584fdffff31951cfdffff2b851cfe }

condition:
	$a0
}

        
