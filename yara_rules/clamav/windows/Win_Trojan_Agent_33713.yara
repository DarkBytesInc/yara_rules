rule Win_Trojan_Agent_33713
{
strings:
	$a0 = { 3845895914e30fbe5fef2c000280a97d296c740faefab7537631031abe8847df864e828fe9b0feda018ce49a80dc90f654c9af4b3732a55eb09a1a2613c31b19cfca34beb3f0c2bb6ec09fbe6bd0096554fd5fcfea096f9520de0894ed71bb }

condition:
	$a0
}

        
