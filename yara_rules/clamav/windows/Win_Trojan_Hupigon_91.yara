rule Win_Trojan_Hupigon_91
{
strings:
	$a0 = { f7a61d718f375fb713f7e50f080ddd800eb77b2851e3d901c7b3f27a4e5a633de57e5fb6026cbea8ed14dec398b47f99e352bc717b316a734e09132fef8377dbe3389efdb5e9a75ecea1227a82ad4641cdef6897f6d93088f62fdda16debc94de020a42618f68a6076720408aa1e46e95b25b122e969eadacdf8cdd64a0b0c801850bfd834 }

condition:
	$a0
}

        