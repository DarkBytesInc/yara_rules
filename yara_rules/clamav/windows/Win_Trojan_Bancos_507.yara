rule Win_Trojan_Bancos_507
{
strings:
	$a0 = { d844ae64214d95e156661085cf4bc464278eff494cbb7379f1a66ca85f70ad466fb690cb772c8aec569f56b66743837f8ec6fdb3f5eea9643688a2a9a1e3c262e98e4da4b808a7982bafe3e7023b8403254a930d18ac124b0cbba4a7e5b713697d8b2425a746337a4dd1c1ab85845e4b9b8383c576a0e16aeddef0929e34c2bfbdd0c3dcad0efe9691c7360e3e8618b07669b0d50617 }

condition:
	$a0
}

        