rule Win_Trojan_PcClient_38
{
strings:
	$a0 = { c3f2c27aef60272b8812316249660edd45a856efbc46c4e9fb351b0db9943a37c4427155d3c5f3023eab7a4adadec03120a95a316492d470166871bcbebcbfaf10c332a8cc3ab18671b355baff3ceb0cb516353e8dddcaf9753e5b083003a1ceff73c42047bfc2722423e0a18e170c83fb2080e498ea05f40cbe82e0dcc707f5e3d6db329bf214f7b070045ced9a95c63ffa2fca1ab9 }

condition:
	$a0
}

        