rule Win_Trojan_Hupigon_1131
{
strings:
	$a0 = { 00a483151414647e8ac40a10089bb206906e77ad2dee6771bcce7338fe1dfc079dccee40b7bcc817c3ba0def39038daec57160bcabb22b480378e482d7012d7241b5cd05e39b05b7341e3724829900bc7241c73205e72e416e7722d5b80bce665b7f0effffffb7dfef5ebdfbfbbf3e7bf9f7dfcf9f3777f6f5e7e82285c60f20c167b3d9ac962de868cfa7ff }

condition:
	$a0
}

        