rule Win_Trojan_Mybot_4955
{
strings:
	$a0 = { dd48288f712655e80d1e893d8058a3f486ead4bc3b9cae611839fa99fcd5e28d88d219766fd813036f8a4062b7e6b38e924ad68f2ac8aa6548fa9f58a168adf0a01e2b58774d0db6ca5612c96e1e }

condition:
	$a0
}

        
