rule Win_Downloader_Banload_696
{
strings:
	$a0 = { 063a460c72cea39cb940df76699c8868d2ec2ff7aedf27c41050f3fdeb464e8eca810fc577b2fa2d4532dd46c86b01dc3b4143067619ee3ec78f559c48eee210238625c226f7c5d516101508047e9ddf2718c829b2d94c632fab8195d1f8310a13246af7c664140cef207354188d3ff0df81eb9e312cd754575a6dc953946bda }

condition:
	$a0
}

        