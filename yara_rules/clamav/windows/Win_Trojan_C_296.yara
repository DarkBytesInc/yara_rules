rule Win_Trojan_C_296
{
strings:
	$a0 = { 5669727573207b477d656e657261746f722056312e3030 }
	$a1 = { 676f745f73617373657240686f746d61696c }

condition:
	$a0 and $a1
}

        
