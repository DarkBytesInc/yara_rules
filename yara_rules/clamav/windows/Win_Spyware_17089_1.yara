rule Win_Spyware_17089_1
{
strings:
	$a0 = { 7910ccc05c16dad368a6550cfbd17a4c49fdb2dd233f792dbfbc971fd3fab873418ea33a737aee5af106da95d74b547f207e68e419612a67f5af122776d31ec290963a97c65d66387cb766cbdaa278f5fc345dd372343c5dbba22589122054b3214aedd6dd5bf26b739794d46a3b609432aad26533774726be6d6beb6da76d76282975fdfcd5b6ffe2a0a8182661def2 }

condition:
	$a0
}

        