rule Win_Trojan_Ciadoor_10
{
strings:
	$a0 = { 50ff4af501000000aefd6910fff5010000006c50ff0b97000c003150ff3510ff6c4cff4348ff6c50ff4344ff6c50ff434cff6c6cfff504000000aa71 }
	$a1 = { 759918403c3e3b2d4941fe062f25fffffffffdff063efefe41422d281b0e0689bccac5000e5f2d194241fefe3e06fffffffdfdff29fefe3efe233527ce1b435c9fa20143eb7b272dfefe3efefe29fffffffffffffefefefefe }

condition:
	$a0 and $a1
}

        
