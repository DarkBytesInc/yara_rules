rule Win_Worm_Nyxem_7
{
strings:
	$a0 = { adce974dff0374db4d7367ffff23540ce2cf12d70a0b53007c7c6d79736f756c6d7501bebdfd7374666c79200f206f6608696e656845b7f6bf421f106576696c7061120a0d0a0befffbb200068746d6c204578706c6f697465204774dd0bfdfe74686573756e20220012fe17ff307479d6dc2f74bf02bc50616e64617e09ba5b }

condition:
	$a0
}

        