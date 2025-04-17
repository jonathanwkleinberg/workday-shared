import requests
import datetime
import re
import pathlib, zipfile
import xml.etree.ElementTree as ET

def dict_extract_by_key(var, key, kv_match=None):
  if hasattr(var,'items'):
    for k, v in var.items():
      if kv_match:
        km, vm = kv_match
        if key in var and km == k and vm == v: yield var[key]
      else:
        if k == key: yield v
      if isinstance(v, dict):
        for result in dict_extract_by_key(v, key, kv_match): yield result
      elif isinstance(v, list):
        for d in v:
          for result in dict_extract_by_key(d, key, kv_match): yield result

def register_cc_api_client(base_url, cc_tenant, username, password, client_name, redirect_uri):
  rs = requests.Session()
  # r = rs.post(auth_url, data={'userName':username, 'password':password}, allow_redirects=False)
  # r2 = rs.send(r.next, allow_redirects=False)
  # 'X-Workday-Client': '2024.18.15'
  auth_url = F'{base_url}/wday/authgwy/{cc_tenant}/login-auth.xml'
  r = rs.post(auth_url, headers={'X-Workday-Client': ''}, data={'userName':username, 'password':password})
  r.raise_for_status()
  if not '"result":"SUCCESS"' in r.text:
    if 'Invalid user name or password' in r.text:
      raise Exception('Invalid user name or password.')
    if 'The URL you have provided is invalid.' in r.text:
      raise Exception('Invalid URL (cc/tenant name).')
  # print(r.json())

  client_api_url = F'{base_url}/{cc_tenant}/task/2997$20813.htmld' # no /d/ to get json
  try:
    AL_API_Client_Result = rs.get(client_api_url).json()
  except:
    raise Exception('Error accessing Advanced Load API Client - Setup page!')
  try:
    flowKey = next(dict_extract_by_key(AL_API_Client_Result, 'flowExecutionKey'))
    sessionSecureToken = next(dict_extract_by_key(AL_API_Client_Result, 'sessionSecureToken'))
    client_name_id = next(dict_extract_by_key(AL_API_Client_Result, 'id', ("label", "Client Name")))
    redirect_uri_id = next(dict_extract_by_key(AL_API_Client_Result, 'id', ("label", "Redirection URI")))
    sequence_task_id = next(dict_extract_by_key(AL_API_Client_Result, 'id', ("propertyName", "nyw:sequence_task"))) # ??? ("widget", "vbox")
  except StopIteration as si:
    si.add_note('Element not found on AL API Client - Setup page!')
    raise si
  # print(flowKey, sessionSecureToken, client_name_id, redirect_uri_id, sequence_task_id)
  # print(list(dict_extract_by_key(AL_API_Client_Result, 'id')))
  # ['90/wd:OAuth_2.0_Client_Name', '90/wd:OAuth_2.0_Redirect_URI', '90/wd:URL_from_Address_Bar', '90/wd:OAuth_2.0_Client_Disabled', '89', 'max-length-row', 'max-length-row', '90.79', '95']

  flowController_url = F'{base_url}/{cc_tenant}/flowController.htmld'

  # Set Client Name
  data = {
    '_flowExecutionKey': flowKey, # e0s1
    client_name_id: client_name, # 90/wd:OAuth_2.0_Client_Name': 'DAI AL API Client'
    '_eventId_validate': client_name_id, # 90/wd:OAuth_2.0_Client_Name'
    'sessionSecureToken': sessionSecureToken,
    # 'clientRequestID': 'cac5267fdd1449f183cf7af4aa170739',
  }
  r = rs.post(flowController_url, data=data)
  r.raise_for_status()
  # print(r.text)

  # Set Redirect URI
  data = {
    '_flowExecutionKey': flowKey, #e0s1
    redirect_uri_id: redirect_uri, # '90/wd:OAuth_2.0_Redirect_URI': 'https://127.0.0.1/'
    '_eventId_validate': redirect_uri_id, # '90/wd:OAuth_2.0_Redirect_URI'
    'sessionSecureToken': sessionSecureToken,
    # 'clientRequestID': '41b98d99ccca405ebef10aa5df57f0a0',
  }
  r = rs.post(flowController_url, data=data)
  r.raise_for_status()
  # print(r.text)

  # Submit Form and Get Client ID & Secret
  data = {
    '_flowExecutionKey': flowKey, #e0s1
    '_eventId_submit': sequence_task_id, # '95'
    'sessionSecureToken': sessionSecureToken,
    # clientRequestID: d88ed90ca0ca481fa8317add193a5dc3
  }
  r = rs.post(flowController_url, data=data)
  try:
    rj = r.json()
  except:
    raise Exception('Error retrieving Client ID & Secret!')
  # print(list(dict_extract_by_key(rj, 'value')))
  # ['DAI AL API Client', 'https://127.0.0.1/', False, 'Below is your Client ID and Client Secret.', 'M2E4MzBhN2ItZWE3NC00ZTNmLWFmNzMtNjY3MzYzMDlhOGQ1', 'o3j6zxfahok9b0fudf34c4varmxdvwoozhrq1llr443s0qbvdk30h1ysy52n6nd7ituq6wmbj84aw70w9qoppridpf73fieng42', 'Advanced Load API Client - Setup', 'Advanced Load API Client - Setup']
  client_id = next(dict_extract_by_key(rj, 'value', ('label', 'Client ID')))
  client_secret = next(dict_extract_by_key(rj, 'value', ('label', 'Client Secret')))
  return client_id, client_secret

def get_auth_token(base_url, cc_tenant, client_id, client_secret, username, password):
  auth_url = F'{base_url}/wday/authgwy/{cc_tenant}/login-auth.xml'
  rs = requests.session()
  r = rs.post(auth_url, headers={'X-Workday-Client': ''}, data={'userName':username, 'password':password})
  r.raise_for_status()
  if not '"result":"SUCCESS"' in r.text:
    if 'Invalid user name or password' in r.text:
      raise Exception('Invalid user name or password.')
    if 'The URL you have provided is invalid.' in r.text:
      raise Exception('Invalid URL (cc/tenant name).')
  # print(r.text)

  code_url = F'{base_url}/wday/authgwy/{cc_tenant}/authorize?response_type=code&client_id={client_id}'
  r = rs.post(code_url, headers={'X-Workday-Client': ''}, allow_redirects=False) # Stop the redirect, we just want the code
  r.raise_for_status()
  if 'Auth Gateway Error' in r.text:
    raise Exception('Error getting Authentication Code - Check your Client ID')
  if 'consentOAuth' in r.text:
    sessionSecureToken = re.findall('(?:sessionSecureToken="(.*))"|$', r.text)[0]
    # print(sessionSecureToken)

    # Send consent
    data = {'consent': 'Allow', 'sessionSecureToken': sessionSecureToken}
    # https://i-01500fc70881f5f19.workdaysuv.com/wday/authgwy/customercentral/consentOAuth
    consent_url = F'{base_url}/wday/authgwy/{cc_tenant}/consentOAuth'
    r = rs.post(consent_url, data=data, allow_redirects=False) # Stop the redirect, we just want the code

  # print(r.text)
  code = r.next.path_url.split('=')[-1]

  # Get Token
  oauth_url = F'{base_url}/ccx/oauth2/{cc_tenant}/token'
  data = {'grant_type': 'authorization_code', 'code': code}
  r = rs.post(oauth_url, auth=(client_id, client_secret), data=data)
  r.raise_for_status()
  # print(r.text)
  rj = r.json()
  return rj['token_type'], rj['access_token']

def get_auth_token_basic(base_url, cc_tenant, username, password):
  auth_url = F'{base_url}/ots/{cc_tenant}/services/security/v1/authIdToken'
  token = requests.get(auth_url, auth=(username,password)).json().get('encodedToken')
  return 'ID', token

def parse_xlsx(fname, use_row_dict=True):
  z = zipfile.ZipFile(fname)
  strings = [el.text for e, el in ET.iterparse(z.open('xl/sharedStrings.xml')) if el.tag.endswith('}t')]
  sheet_names = {next(y[1] for y in x.attrib.items() if y[0].endswith('}id')).replace('rId',''):x.attrib.get('name') for _, x
in ET.iterparse(z.open(R'xl/workbook.xml')) if x.tag.endswith('sheet')}
  sheets = {}
  rows = []
  # Init element vars
  row = {} if use_row_dict else []
  value = ''
  # for sheet in [x for x in z.namelist() if re.search('xl/worksheets/sheet*.xml', x)]:
  for idx, sheet_name in sheet_names.items():
    sheet = F'xl/worksheets/sheet{idx}.xml'
    for e, el in ET.iterparse(z.open(sheet)):
      if el.tag.endswith('}v'): value = el.text # <v>84</v>
      if el.tag.endswith('}c'):  # <c r="A3" t="s"><v>84</v></c>
        if el.attrib.get('t') == 's': value = strings[int(value)]
        column_name = ''.join(x for x in el.attrib['r'] if not x.isdigit())  # AZ22
        if use_row_dict: row[column_name] = value
        else: row.append(value)
        value = ''
      if el.tag.endswith('}row'):
        rows.append(row)
        row = {} if use_row_dict else []
    sheets[sheet_name] = rows
  return sheets

def process_loadset_folder(files_path):
  files_path = pathlib.Path(files_path)
  set_def_file = files_path / 'Set Definition.xlsx'
  if not set_def_file.is_file():
    raise Exception('Missing file "Set Definition.xlsx"')
  sheets = parse_xlsx(set_def_file)
  if not 'Set Definition' in sheets:
    raise Exception('Missing sheet "Set Definition" from file.')
  
  set_def_iter = iter(sheets['Set Definition'])
  headers = next(set_def_iter)

  file_name_col = next(x for x in headers if 'File Name' in headers[x])
  impl_type_col = next(x for x in headers if 'Implementation Type' in headers[x])
  impl_comp_col = next(x for x in headers if 'Implementation Component' in headers[x])
  version_col   = next(x for x in headers if 'Web Service Version' in headers[x])
  
  content = []
  loadSetFiles = []
  order = 0
  for row in set_def_iter:
    file_name = row.get(file_name_col)
    impl_type = row.get(impl_type_col)
    impl_comp = row.get(impl_comp_col)
    version   = row.get(version_col)

    if file_name and (files_path / file_name).is_file():
      order += 1
      add_content = {
        "order": order,
        "fileName": file_name,
      }
      if impl_type: add_content['implementationType'] = impl_type
      if impl_comp: add_content['implementationComponent'] = impl_comp
      if version: add_content['version'] = version
      content.append(add_content)
      add_loadSetFile = {
        "sourceType": "fileUpload",
        "fileName": file_name,
        "id": "TBD"
      }
      loadSetFiles.append(add_loadSetFile)
    else:
      continue

  loadset_data = {
    "setName": F"Demo Set Advanced Load for HCM - {datetime.datetime.now()}",
    "setDefinition": {
      "sourceType": "json",
      "content": content
      # [{ "order": "a",
      #    "fileName": "Visa ID Types.xlsx",
      #    "implementationType": "Visa ID Types",
      #    "version": "v41.1" }]
    },
    "loadSetFiles": loadSetFiles
    # [{"sourceType": "fileUpload", "fileName": "Visa ID Types.xlsx", "id": "Visa ID Types"}]
  }
  return loadset_data

def upload_files(base_url, cc_tenant, token_type, token, loadset_data, files_dir, basic_auth=False, verify=True):
  for file_data in loadset_data['loadSetFiles']:
    if basic_auth:
      files_url = F'{base_url}/data-loader/implementation/v1alpha/files/{file_data['fileName']}'
    else:
      # https://[suv_id].workdaysuv.com:11714/impl/v1alpha/files  for HTTPS (might give TLS issues)
      # http://[suv_id].workdaysuv.com:11710/impl/v1alpha/files  for plain HTTP
      files_url = F'{base_url.replace('https', 'http')}:11710/impl/v1alpha/files/{file_data['fileName']}'
    headers = {
      'Authorization': F"{token_type} {token}",
      'X-Tenant':cc_tenant,
      'Content-Type':'application/octet-stream', 
      'Originator': 'DAI Script'
    } 
    with open(files_dir / file_data['fileName'], 'rb') as f:
      data = f.read()
    r = requests.post(files_url, headers=headers, data=data, verify=verify)
    r.raise_for_status()
    try:
      rj = r.json()
      # print(rj)
      file_data['id'] = rj['id']
    except Exception as e:
      e.add_note('Error Uploading File or Retrieving ID')
      raise(e)

def send_load_sets(base_url, cc_tenant, token_type, token, loadset_data, basic_auth=False, verify=False):
  if basic_auth:
    loadsets_url = F'{base_url}/data-loader/implementation/v1alpha/loadsets'
  else:
    # https://[suv_id].workdaysuv.com:11714/impl/v1alpha/loadsets  for HTTPS (might give TLS issues)
    # http://[suv_id].workdaysuv.com:11710/impl/v1alpha/loadsets  for plain HTTP
    loadsets_url = F'{base_url.replace('https', 'http')}:11710/impl/v1alpha/loadsets'
  headers = {
    'Authorization': F"{token_type} {token}",
    'X-Tenant':cc_tenant,
    # 'Content-Type':'application/json', 
    # 'Accept': 'application/json',
    'Originator': 'DAI Script'
  } 
  r = requests.post(loadsets_url, headers=headers, json=loadset_data, verify=verify)
  r.raise_for_status()
  print(r.text)

if __name__ == "__main__":
  base_url = 'https://i-01500fc70881f5f19.workdaysuv.com'
  cc_tenant = 'customercentral'
  ccs_username = 'ccs' # CC Security Admin
  ccs_password = '6%U@Dcm5ZTouQ8vH'
  username = 'ccu' # CC User / Implementer
  password = ccs_password
  client_name = F'DAI AL API Client - {datetime.datetime.now()}'
  redirect_uri = 'https://127.0.0.1/'

  basic_auth = False

  client_id = None
  client_secret = None
  # client_id = 'YTIxNWRjYTYtZjgzNy00MjNjLTk3NmMtOTFiYWE3NjU4MmRh'
  # client_secret = '8fqtzsxrs1nvvlizcok6rp7ugh62trrt54todc83rah1tn5jljygepial6ud3wsgo8l94o27genpqy9965qit913v3empsu174b'

  current_dir = pathlib.Path(__file__).parent
  files_dir = current_dir / 'files'

  # Register API Client
  if not basic_auth and not client_id:
    client_id, client_secret = register_cc_api_client(base_url, cc_tenant, ccs_username, ccs_password, client_name, redirect_uri)
    print(client_id, client_secret)
  
  # Get Token
  if basic_auth:
    token_type, token = get_auth_token_basic(base_url, cc_tenant, username, password)
  else:
    token_type, token = get_auth_token(base_url, cc_tenant, client_id, client_secret, username, password)
  print(token_type, token)

  # AL Loadsets API call  
  loadset_data = process_loadset_folder(files_dir)
  # print(loadset_data)

  upload_files(base_url, cc_tenant, token_type, token, loadset_data, files_dir, basic_auth, verify=True if basic_auth else False)
  print(loadset_data)

  send_load_sets(base_url, cc_tenant, token_type, token, loadset_data, basic_auth, verify=True if basic_auth else False)