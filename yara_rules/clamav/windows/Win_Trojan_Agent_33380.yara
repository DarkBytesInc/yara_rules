rule Win_Trojan_Agent_33380
{
strings:
	$a0 = { ab257f28b7c74fad425e55b9bc2ecafa87e7de4acd2c4f38fcea440139ff4da96cec413cb47e5b3db6b41a591f08bd838a8822dba4c58af787211781944086060d155de8e5a4560bfdf48752ed175fa2be8d78e38adea5fd487126b4 }

condition:
	$a0
}

        
