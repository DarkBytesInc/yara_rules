rule Win_Trojan_Spabot_10
{
strings:
	$a0 = { 2e302a90e74ebdb5679e3f93eae4a65665a394f6217307579563b7b1445bb49150b60f29134ab9403ae538d644366b448dd2b3acb9f343445b654dffa86a7bac4d2a0f904d9216b503316568fa676b4d61f005b7cbcc6a5d4226a0ebf75ea5f3892e15520d0fa9e2114ea5eecc4bec97a25a8f14dd6fd4957c0886d3b4bf1ab3cb5401ee49e8184dcef17858a7b931c3 }

condition:
	$a0
}

        