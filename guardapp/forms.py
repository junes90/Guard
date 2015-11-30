from django import forms

class PolicyForm(forms.Form):
	 IFACE = forms.CharField(widget=forms.Select(choices=(('eth0',u'eth0'),('eth1',u'eth1'),)))
	 RULE = forms.CharField(widget=forms.Select(choices=(('ACCEPT',u'ACCEPT'),('DROP',u'DROP'),)))
	 NAME = forms.CharField() 
	 PROTOCOL = forms.CharField(widget=forms.Select(choices=(('all',u'All'),('tcp',u'TCP'),('udp',u'UDP'),('icmp',u'ICMP'),)))
	 Src_IP = forms.GenericIPAddressField(initial='0.0.0.0')
	 Src_Port = forms.IntegerField(initial='0')
	 Dst_IP = forms.GenericIPAddressField(initial='0.0.0.0')
	 Dst_Port = forms.IntegerField(initial='0')

class DelForm(forms.Form): 
	 NUM = forms.IntegerField()
