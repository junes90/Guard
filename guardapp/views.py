from django.http import HttpResponse
from django.shortcuts import render
from django.shortcuts import render_to_response
from django.views.generic import TemplateView 
from .forms import PolicyForm, DelForm

import subprocess

# Create your views here.
def display_sys(request):
	p = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/cpu'],
			 stdout=subprocess.PIPE)
	p1 = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/mem'],
			 stdout=subprocess.PIPE)
	p2 = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/disk'],
			 stdout=subprocess.PIPE)
	cpu_out, cpu_err = p.communicate()
	mem_out, mem_err = p1.communicate()
	disk_out, disk_err = p2.communicate()
	return render_to_response('dash.html', {'cpu': cpu_out, 'mem': mem_out, 'disk': disk_out}) 

def whitelist(request):
	whiteform = PolicyForm(request.POST or None)
	delform = DelForm(request.POST or None)
	if whiteform.is_valid():
		iface = whiteform.cleaned_data['IFACE']
		rule = whiteform.cleaned_data['RULE']
		name = whiteform.cleaned_data['NAME']
		proto = whiteform.cleaned_data['PROTOCOL']
		sip = whiteform.cleaned_data['Src_IP']
		sport = whiteform.cleaned_data['Src_Port']
		dip = whiteform.cleaned_data['Dst_IP']
		dport = whiteform.cleaned_data['Dst_Port']
		
		if str(proto) == 'tcp' or str(proto) == 'udp':
		    iptables_command = ['iptables', '-A', 'INPUT',]
		    parameter = ['-j', 'LOG', '--log-prefix', 'guard', '-i', str(iface), '-p', str(proto), '-s', str(sip), '--sport', str(sport), '-d', str(dip), '--dport', str(dport)]
		    iptables_command.extend(parameter)
	            result = subprocess.call(iptables_command)

		    iptables_command = ['iptables', '-A', 'INPUT',]
		    parameter = ['-j', str(rule), '-i', str(iface), '-p', str(proto), '-s', str(sip), '--sport', str(sport), '-d', str(dip), '--dport', str(dport)]
		    iptables_command.extend(parameter)
		    result = subprocess.call(iptables_command)

		else:
		    iptables_command = ['iptables', '-A', 'INPUT',]
		    parameter = ['-j', 'LOG', '--log-prefix', 'guard', '-i', str(iface), '-p', str(proto), '-s', str(sip), '-d', str(dip)]
		    iptables_command.extend(parameter)
	            result = subprocess.call(iptables_command)

		    iptables_command = ['iptables', '-A', 'INPUT',]
		    parameter = ['-j', str(rule), '-i', str(iface), '-p', str(proto), '-s', str(sip), '-d', str(dip)]
		    iptables_command.extend(parameter)
		    result = subprocess.call(iptables_command)
		
	if delform.is_valid():
		num = delform.cleaned_data['NUM']

		iptables_command = ['iptables', '-D', 'INPUT',]
		parameter = [str(num),]
		iptables_command.extend(parameter)
		result = subprocess.call(iptables_command)

	white_num = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_num'], 
			stdout=subprocess.PIPE)
	white_iface = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_iface'], 
			stdout=subprocess.PIPE)
	white_rule = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_rule'], 
			stdout=subprocess.PIPE)
	white_proto = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_proto'], 
			stdout=subprocess.PIPE)
	white_sip = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_sip'], 
			stdout=subprocess.PIPE)
	white_sport = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_sport'], 
			stdout=subprocess.PIPE)
	white_dip = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_dip'], 
			stdout=subprocess.PIPE)
	white_dport = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/whitelist_dport'], 
			stdout=subprocess.PIPE)

	num_out, num_err = white_num.communicate()
	i_out, i_err = white_iface.communicate()
	rule_out, rule_err = white_rule.communicate()
	proto_out, proto_err = white_proto.communicate()
	sip_out, sip_err = white_sip.communicate()
	sport_out, sport_err = white_sport.communicate()
	dip_out, dip_err = white_dip.communicate()
	dport_out, dport_err = white_dport.communicate()

	return render(request, 'white.html', {'whiteform': whiteform, 'delform': delform, 'white_iface': i_out, 'white_num': num_out, 'white_rule': rule_out, 'white_proto': proto_out, 'white_sip': sip_out, 'white_sport': sport_out, 'white_dip': dip_out, 'white_dport': dport_out})

def display_monitor(request):
	return render(request, 'monitor.html', )

def display_log(request):
	p = subprocess.Popen(['sh', '/home/junes90/guard/guardapp/bin/log'],
			 stdout=subprocess.PIPE)
	log_out, log_err = p.communicate()
	return render(request, 'log.html', {'log': log_out}) 
