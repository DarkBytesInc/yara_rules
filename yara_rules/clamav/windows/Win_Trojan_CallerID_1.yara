rule Win_Trojan_CallerID_1
{
strings:
	$a0 = { 44014558414d504c45010a50312d3830302d35012d31a54c32020211061f50052049156e73443d696e67525120433f539b6f6620154a0220541e689073747552516c64666b6b6162a5aa0c6a61ad2c809f0865023025 }

condition:
	$a0
}

        