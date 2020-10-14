from lxml import etree
from datetime import datetime
import random


def generate_xml_format():
    root = etree.Element('MetasploitV4')
    create_tree = generate_xml(root)
    file_name = str(input('file name: '))
    with open(file_name, "wb") as f: 
        f.write(create_tree) 
        f.close()

def generate_xml(root):

    created_hosts = []

    hosts = int(input('hosts: ')) #click
    services = int(input('services per host: ')) #click
    vulns = int(input('vulns per service: ')) #click
    
    print(vulns*services*hosts, ' vulns')
    
    x = 0
    while x < hosts:
        x+=1
        hosts_tag = etree.SubElement(root, 'hosts')
        host_tag = etree.SubElement(hosts_tag, 'host')
        host_id_tag = etree.SubElement(host_tag, 'id')
        host_id_tag.text = str(random.choice(range(100,1000)))
        
        host_created_at_tag = etree.SubElement(host_tag, 'created_at')
        dt = datetime.now()
        host_created_at_tag.text = str(dt.replace(second=0, microsecond=0))

        host_address_tag = etree.SubElement(host_tag, 'address')
        host_address_tag.text = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        if host_address_tag.text not in created_hosts:
            created_hosts.append(host_address_tag.text)
            

        host_mac_tag = etree.SubElement(host_tag, 'mac')
        host_mac_tag.text = "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255),
                                random.randint(0, 255))

        host_name_tag = etree.SubElement(host_tag, 'name')
        host_name_tag.text = ''

        os = ['Windows', 'Mac', 'Linux']
        host_os_name_tag = etree.SubElement(host_tag, 'os-name')
        host_os_name_tag.text = random.choice(os)

        host_updated_at_tag = etree.SubElement(host_tag, 'updated-at')
        host_updated_at_tag.text = str(dt.replace(second=0, microsecond=0))

        host_comments_tag = etree.SubElement(host_tag, 'comments')
        host_comments_tag.text = ''

        host_vuln_count_tag = etree.SubElement(host_tag, 'vuln-count')
        host_vuln_count_tag.text = str(vulns)

        host_service_count_tag = etree.SubElement(host_tag, 'service-count')
        host_service_count_tag.text = str(services)

        host_comm_tag = etree.SubElement(host_tag, 'comm')
        host_state_tag = etree.SubElement(host_tag, 'state')
        host_os_flavor_tag = etree.SubElement(host_tag, 'os-flavor')
        host_os_sp_tag = etree.SubElement(host_tag, 'os-sp')
        host_os_lang_tag = etree.SubElement(host_tag, 'os-lang')
        host_purpose_tag = etree.SubElement(host_tag, 'purpose')

        services_tag = etree.SubElement(host_tag, 'services')
        count_service = 0
        while count_service < services:
            count_service+=1
            service_tag = etree.SubElement(services_tag,'service')

            service_id_tag = etree.SubElement(service_tag, 'id')
            service_id_tag.text = str(random.choice(range(100,1000)))

            service_created_at_tag = etree.SubElement(service_tag, 'created_at')
            service_created_at_tag.text = str(dt.replace(second=0, microsecond=0))

            service_host_id_tag = etree.SubElement(service_tag, 'host-id')
            service_host_id_tag.text = host_id_tag.text

            service_port_tag = etree.SubElement(service_tag, 'port')
            service_port_tag.text = str(random.choice(range(1,65535)))

            service_proto_tag = etree.SubElement(service_tag, 'proto')
            proto = ['TCP', 'UDP']
            service_proto_tag.text = random.choice(proto)

            service_state_tag = etree.SubElement(service_tag, 'state')
            state = ['open', 'close']
            service_state_tag.text = random.choice(state)

            service_name_tag = etree.SubElement(service_tag, 'name')
            service_name_tag.text = 'http'

            service_updated_at_tag = etree.SubElement(service_tag, 'updated-at')
            service_updated_at_tag.text = str(dt.replace(second=0, microsecond=0))

            service_info_tag = etree.SubElement(service_tag, 'info')
            service_info_tag.text = ''

            vulns_tag = etree.SubElement(host_tag, 'vulns')
            
            count_vuln = 0
            while count_vuln < vulns:
                count_vuln+=1
                vuln_tag = etree.SubElement(vulns_tag, 'vuln')
                
                vuln_id_tag = etree.SubElement(vuln_tag, 'id')
                vuln_id_tag.text = str(random.choice(range(100,1000)))

                vuln_host_id_tag = etree.SubElement(vuln_tag, 'host-id')
                vuln_host_id_tag.text = host_id_tag.text
                vuln_service_id_tag = etree.SubElement(vuln_tag, 'service-id')
                vuln_service_id_tag.text = service_id_tag.text
                vuln_web_site_id_tag = etree.SubElement(vuln_tag, 'web-site-id')
                vuln_web_site_id_tag.text = service_id_tag.text

                vuln_name_tag = etree.SubElement(vuln_tag, 'name')
                vuln_name_tag.text = 'vuln {d}'.format(d = str(random.choice(range(1,1000))))

                vuln_info_tag = etree.SubElement(vuln_tag, 'info')
                vuln_info_tag.text = 'description n: {a}'.format(a = str(random.choice(range(1,1000))))
                vuln_refs_tag = etree.SubElement(vuln_tag, 'refs')

    root_services_tag = etree.SubElement(root, 'services')

    root_service_tag = etree.SubElement(root_services_tag, 'service')

    root_id_tag = etree.SubElement(root_service_tag, 'id')
    root_id_tag.text = service_id_tag.text

    root_created_at_tag = etree.SubElement(root_service_tag, 'created-at')
    root_created_at_tag.text = service_created_at_tag.text
    
    root_host_id_tag = etree.SubElement(root_service_tag, 'host-id')
    root_host_id_tag.text = host_id_tag.text

    root_port_tag = etree.SubElement(root_service_tag, 'port')
    root_port_tag.text = service_port_tag.text

    root_proto_tag = etree.SubElement(root_service_tag, 'proto')
    root_proto_tag.text = service_proto_tag.text

    root_state_tag = etree.SubElement(root_service_tag, 'state')
    root_state_tag.text = service_state_tag.text

    root_name_tag = etree.SubElement(root_service_tag, 'name')
    root_name_tag.text = service_name_tag.text

    root_updated_at_tag = etree.SubElement(root_service_tag, 'updated-at')
    root_updated_at_tag.text = service_updated_at_tag.text
    
    root_info_tag = etree.SubElement(root_service_tag, 'info')
    root_info_tag.text = ''

    websites_tag = etree.SubElement(root, 'web_sites')
    web_vulns_tag = etree.SubElement(root, 'web_vulns')


    create_tree = etree.tostring(root, pretty_print=True)
    return create_tree

if __name__ == "__main__":
    generate_xml_format()
