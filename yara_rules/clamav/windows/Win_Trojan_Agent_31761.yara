rule Win_Trojan_Agent_31761
{
strings:
	$a0 = { d4d8716258c8d3db888d9eaa4441d4cbd69ac76b834eef6f89def179c1c8498a8830beab1acf498a809cf4a2f5a6f2b5adaae97e89c710b5d3df6eaf89ce1287ecbdfaa3f7aee5b9eca1b19ee63094d174bbddbfe4c7cdcfd1aa }

condition:
	$a0
}

        
