rule Win_Trojan_Bifrose_595
{
strings:
	$a0 = { 8206afd616982b3a6d38ffea7e3c418e89fe8153d5af47ba6cda2b5e1e52117423422238f94aa18d706917a08bc9fe004d0fcc8668b9c19c2be746a047e0505a511f7c7a114f11e65c9c900571ea04a866c308875c288b414d0e0966c548854a535bb19fb84c564b0681c126b41a540a5c8a5362a503eb53821862d6111c3af64268ac592b28fb29a40cea84948598294af9a107fcc0 }

condition:
	$a0
}

        