rule Win_Proxy_Horst_144
{
strings:
	$a0 = { 13807244b24044b240ea3c150bf50d0be44b0072c8b140f9e481e444b24020b94044b240f20314048ca8b840e40b893c00b640a4b8400005af3b0423a310e41bf2858ca4b8402f1685fc15542068cd4045f210f280cd4000b140098c58f2f09040c8aca0960593205a594a9e80cd403d29f9b2822068cd4057f22be480cd4083ffffffd4909f7cc990403490407bfeffff2ba895 }

condition:
	$a0
}

        