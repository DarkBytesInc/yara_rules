rule Win_Trojan_Hupigon_1077
{
strings:
	$a0 = { 1cf09f74f3180413f2112d705998ac11fb1638c48e77fda2bc11de1204364a714854ca5ef7c60c296641cabd1dd8635675af373665b6ba772d6f8635f535380de4e4b26c21e2ac73d01151b9e1afe8afc8dc7ac498027d5a9576fb389d4ed6f4bbbb77dff64de30df9b885f4ff3b082e410dd4e35ad48574afa55591986afffae21ce98e1758876abbb8b1b3 }

condition:
	$a0
}

        