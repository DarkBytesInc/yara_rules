rule Win_Downloader_Zlob_1635
{
strings:
	$a0 = { 8f95d2348a1963c65716fb5a566904028c53902e02fa4ad731d51e5fbcd20ae95d600eee52eca0da85fe60895e2af38201b6600aab99014ee4253e73e42807943c1aee12d325d7e0d92108c8d08db43e57e5d5699c9f347b911b753bb119f84193b7e5d8a8060f7d10af012c6f899df1922b66552c7ceaf963f165c0dbb0374cb209fb90af172d6b1b9d56e32a754ce12de0714715de }

condition:
	$a0
}

        