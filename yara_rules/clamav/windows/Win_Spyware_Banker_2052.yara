rule Win_Spyware_Banker_2052
{
strings:
	$a0 = { 987ea89f8ddcfa8abe58d9dc80a071abc8b32fac156a136e1a1a3365c9fc22c896827063764e36680d251ea5d993ab30395eb8f31c327df1d63384f071dff043bb0fbf811f151227a97943b2ee24617933b5a17347436d38e79898ce079065c9233d2a3ae92edc640290e70c84374edd220cb16a60cda2ad69fc8fe67e2509ea }

condition:
	$a0
}

        