rule Win_Tool_MailSpam_2
{
strings:
	$a0 = { 616d65004176616c616e6368650000001800050046696c6556657273696f6e00332e3030000000001c00050050726f64 }

condition:
	$a0
}

        