rule Win_Spyware_Banker_3927
{
strings:
	$a0 = { 0a483150414647b14881434089bdc81a41bcabc6bcfc6de679e670fc3cfc079e6679902de73205b739b06de7902b5762be2c17cadd905ac05bc7202d7005ae406d7245be392156e68157241f4c805c7241e5f320dbe6640796e41b79701b79996f3339cffffff6fcfef9f3efdef7aebef5dfdebaeb777f6f9eff022a5c7114a61b359ac961afd9478ef9dff7 }

condition:
	$a0
}

        