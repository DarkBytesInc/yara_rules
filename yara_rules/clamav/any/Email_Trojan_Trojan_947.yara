rule Email_Trojan_Trojan_947
{
strings:
	$a0 = { 446572205a61686c73636865696e20756e64206469652062657374656c6c74656e2050726f64756b7465206c696567656e2064696573657220452d4d61696c[0-8]616c73204265696c61676520626569 }

condition:
	$a0
}

        