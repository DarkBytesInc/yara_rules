rule Win_Trojan_Mybot_5460
{
strings:
	$a0 = { 8f339f1af0f7c49476c71d093de788513d1e2cbcd99dfac68394ebce63fc09da30bb5fe2eaac52fe81f08c97f81c86abbd9181e6a3caeb50c42463e3563dd3ae6d7d4d549d63d8c541786d2df14d6d63ca900388164cbc426841d5b494538cf671e7cb7f32c577316e8aa80177008e7f8d0bff127414170f572dd628fa4a1a913ca295c4ca62801fda1fa8b9 }

condition:
	$a0
}

        