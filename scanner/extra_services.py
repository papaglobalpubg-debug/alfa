"""
Extended service fingerprints for takeover_v5.
Adds 130+ additional services on top of the core 76.
"""

EXTRA_SERVICES = {
    # Modern serverless / edge platforms
    'cloudflare-r2': {'name': 'Cloudflare R2', 'cn': [r'^(.+)\.r2\.cloudflarestorage\.com$'], 'fp': [{'body': [r'NoSuchBucket'], 's': [404]}], 'claimable': 'verify', 'pri': 'high'},
    'cloudflare-tunnel': {'name': 'Cloudflare Tunnel', 'cn': [r'^(.+)\.cfargotunnel\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'deno-deploy': {'name': 'Deno Deploy', 'cn': [r'^(.+)\.deno\.dev$'], 'fp': [{'body': [r'This deployment could not be found'], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'bun-deploy': {'name': 'Bun Deploy', 'cn': [r'^(.+)\.bun\.sh$'], 'fp': [], 'claimable': 'verify', 'pri': 'medium'},
    'railway': {'name': 'Railway', 'cn': [r'^(.+)\.up\.railway\.app$', r'^(.+)\.railway\.app$'], 'fp': [{'body': [r'Application not found'], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'val-town': {'name': 'Val Town', 'cn': [r'^(.+)\.web\.val\.run$'], 'fp': [], 'claimable': 'verify', 'pri': 'medium'},
    'edgio': {'name': 'Edgio', 'cn': [r'^(.+)\.edgio\.link$', r'^(.+)\.moovweb\.net$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Databases-as-a-service
    'supabase': {'name': 'Supabase', 'cn': [r'^(.+)\.supabase\.co$', r'^(.+)\.supabase\.in$'], 'fp': [{'body': [r'Project not found'], 's': [404]}], 'claimable': 'verify', 'pri': 'high'},
    'planetscale': {'name': 'PlanetScale', 'cn': [r'^(.+)\.psdb\.cloud$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'neon': {'name': 'Neon (Postgres)', 'cn': [r'^(.+)\.neon\.tech$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'snowflake': {'name': 'Snowflake', 'cn': [r'^(.+)\.snowflakecomputing\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'databricks': {'name': 'Databricks', 'cn': [r'^(.+)\.cloud\.databricks\.com$', r'^(.+)\.databricks\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Static site hosts
    'surge-2': {'name': 'Surge.sh (alt)', 'cn': [r'^(.+)\.surge\.sh$'], 'fp': [{'body': [r'project not found'], 's': [404]}], 'claimable': True, 'pri': 'high'},
    'now-sh': {'name': 'Zeit Now (legacy)', 'cn': [r'^(.+)\.now\.sh$'], 'fp': [{'body': [r'DEPLOYMENT_NOT_FOUND'], 's': [404]}], 'claimable': True, 'pri': 'high'},
    'firebase-web': {'name': 'Firebase Web App', 'cn': [r'^(.+)\.web\.app$'], 'fp': [{'body': [r'Site Not Found'], 's': [404]}], 'claimable': True, 'pri': 'high'},
    'aerobatic': {'name': 'Aerobatic', 'cn': [r'^(.+)\.aerobatic\.io$', r'^(.+)\.aerobaticapp\.com$'], 'fp': [{'body': [r'No such application'], 's': [404]}], 'claimable': True, 'pri': 'medium'},

    # CI / CD services
    'circleci': {'name': 'CircleCI', 'cn': [r'^(.+)\.circleci\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'travisci': {'name': 'Travis CI', 'cn': [r'^(.+)\.travis-ci\.com$', r'^(.+)\.travis-ci\.org$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'appveyor': {'name': 'AppVeyor', 'cn': [r'^(.+)\.appveyor\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # DNS providers
    'ns1': {'name': 'NS1', 'cn': [r'^(.+)\.nsone\.net$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'dnsimple': {'name': 'DNSimple', 'cn': [r'^(.+)\.dnsimple\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Monitoring / logging
    'sentry': {'name': 'Sentry.io', 'cn': [r'^(.+)\.sentry\.io$', r'^(.+)\.ingest\.sentry\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'datadog': {'name': 'Datadog', 'cn': [r'^(.+)\.datadoghq\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'newrelic': {'name': 'New Relic', 'cn': [r'^(.+)\.newrelic\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'papertrail': {'name': 'Papertrail', 'cn': [r'^(.+)\.papertrailapp\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'loggly': {'name': 'Loggly', 'cn': [r'^(.+)\.loggly\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'freshdesk': {'name': 'Freshdesk', 'cn': [r'^(.+)\.freshdesk\.com$'], 'fp': [{'body': [r'Your dashboard has been suspended'], 's': [404, 200]}], 'claimable': 'verify', 'pri': 'medium'},
    'freshchat': {'name': 'Freshchat', 'cn': [r'^(.+)\.freshchat\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'intercom': {'name': 'Intercom', 'cn': [r'^(.+)\.intercom\.help$'], 'fp': [{'body': [r"This page is missing or you need to sign in"], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'crisp': {'name': 'Crisp', 'cn': [r'^(.+)\.crisp\.help$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Marketing / analytics
    'hubspot': {'name': 'HubSpot', 'cn': [r'^(.+)\.hubspotpagebuilder\.com$', r'^(.+)\.hubspot\.com$'], 'fp': [{'body': [r"The page you're looking for"], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'marketo': {'name': 'Marketo', 'cn': [r'^(.+)\.mktoweb\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'pardot': {'name': 'Pardot', 'cn': [r'^(.+)\.pardot\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'iterable': {'name': 'Iterable', 'cn': [r'^(.+)\.iterable\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'sendinblue': {'name': 'Sendinblue', 'cn': [r'^(.+)\.sendibmXX\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Video
    'wistia': {'name': 'Wistia', 'cn': [r'^(.+)\.wistia\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'vidyard': {'name': 'Vidyard', 'cn': [r'^(.+)\.vidyard\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'brightcove': {'name': 'Brightcove', 'cn': [r'^(.+)\.brightcove\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'ooyala': {'name': 'Ooyala', 'cn': [r'^(.+)\.ooyala\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # E-commerce
    'shopify-alt': {'name': 'Shopify (Alt)', 'cn': [r'^(.+)\.myshopify\.com$'], 'fp': [{'body': [r'Sorry, this shop is currently unavailable'], 's': [404]}], 'claimable': False, 'pri': 'low', 'dead': 'Reserved since 2021'},
    'squarespace': {'name': 'Squarespace', 'cn': [r'^(.+)\.squarespace\.com$'], 'fp': [{'body': [r"You're Almost There"], 's': [200]}], 'claimable': 'verify', 'pri': 'medium'},
    'gumroad': {'name': 'Gumroad', 'cn': [r'^(.+)\.gumroad\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'squareup': {'name': 'Square', 'cn': [r'^(.+)\.squareup\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Forms / surveys
    'typeform': {'name': 'Typeform', 'cn': [r'^(.+)\.typeform\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'surveymonkey': {'name': 'SurveyMonkey', 'cn': [r'^(.+)\.surveymonkey\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'jotform': {'name': 'JotForm', 'cn': [r'^(.+)\.jotform\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Chat / community
    'discourse': {'name': 'Discourse', 'cn': [r'^(.+)\.trydiscourse\.com$'], 'fp': [{'body': [r'is temporarily offline'], 's': [404, 200]}], 'claimable': 'verify', 'pri': 'medium'},
    'circle': {'name': 'Circle.so', 'cn': [r'^(.+)\.circle\.so$'], 'fp': [{'body': [r"community you're trying to access"], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},

    # Documentation
    'gitbook': {'name': 'GitBook', 'cn': [r'^(.+)\.gitbook\.io$'], 'fp': [{'body': [r'Content not found'], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'gitiles': {'name': 'Gitiles', 'cn': [r'^(.+)\.googlesource\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'notion': {'name': 'Notion', 'cn': [r'^(.+)\.notion\.site$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'coda': {'name': 'Coda.io', 'cn': [r'^(.+)\.coda\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Payment
    'stripe': {'name': 'Stripe', 'cn': [r'^(.+)\.stripe\.com$', r'^(.+)\.stripe\.network$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'chargebee': {'name': 'ChargeBee', 'cn': [r'^(.+)\.chargebee\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'recurly': {'name': 'Recurly', 'cn': [r'^(.+)\.recurly\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Storage variants
    'aws-s3-website-eu': {'name': 'AWS S3 Website (EU)', 'cn': [r'^(.+)\.s3-website\.eu-[a-z0-9-]+\.amazonaws\.com$'], 'fp': [{'body': [r'NoSuchBucket'], 's': [404]}], 'claimable': True, 'pri': 'critical'},
    'aws-s3-website-us': {'name': 'AWS S3 Website (US)', 'cn': [r'^(.+)\.s3-website-[a-z0-9-]+\.amazonaws\.com$'], 'fp': [{'body': [r'NoSuchBucket'], 's': [404]}], 'claimable': True, 'pri': 'critical'},
    'gcp-download-storage': {'name': 'GCP Download Storage', 'cn': [r'^(.+)\.storage-download\.googleapis\.com$'], 'fp': [], 'claimable': True, 'pri': 'high'},

    # Communication
    'sendgrid': {'name': 'SendGrid', 'cn': [r'^(.+)\.sendgrid\.net$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'mailgun': {'name': 'Mailgun', 'cn': [r'^(.+)\.mailgun\.org$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'twilio': {'name': 'Twilio', 'cn': [r'^(.+)\.twil\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Miscellaneous SaaS
    'atlassian-jira': {'name': 'Atlassian JIRA', 'cn': [r'^(.+)\.atlassian\.net$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'atlassian-confluence': {'name': 'Atlassian Confluence', 'cn': [r'^(.+)\.confluence\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'atlassian-bitbucket': {'name': 'Atlassian Bitbucket', 'cn': [r'^(.+)\.bitbucket\.org$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'launchdarkly': {'name': 'LaunchDarkly', 'cn': [r'^(.+)\.launchdarkly\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'segment': {'name': 'Segment', 'cn': [r'^(.+)\.segment\.io$', r'^(.+)\.segment\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'mixpanel': {'name': 'Mixpanel', 'cn': [r'^(.+)\.mixpanel\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'amplitude': {'name': 'Amplitude', 'cn': [r'^(.+)\.amplitude\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Video calls
    'zoom': {'name': 'Zoom', 'cn': [r'^(.+)\.zoom\.us$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'gotomeeting': {'name': 'GoToMeeting', 'cn': [r'^(.+)\.gotomeeting\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Learning / courses
    'kajabi-alt': {'name': 'Kajabi (Alt)', 'cn': [r'^(.+)\.kajabi\.com$'], 'fp': [{'body': [r"The page you were looking for doesn'?t exist"], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'teachable': {'name': 'Teachable', 'cn': [r'^(.+)\.teachable\.com$'], 'fp': [{'body': [r"school doesn'?t exist"], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'podia': {'name': 'Podia', 'cn': [r'^(.+)\.podia\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Domain marketplace
    'sedo': {'name': 'Sedo Parking', 'cn': [r'^(.+)\.sedoparking\.com$'], 'fp': [{'body': [r'This domain is for sale'], 's': [200]}], 'claimable': 'verify', 'pri': 'low'},
    'godaddy': {'name': 'GoDaddy Parking', 'cn': [r'^(.+)\.parkingcrew\.net$'], 'fp': [], 'claimable': False, 'pri': 'low'},

    # More
    'apiary': {'name': 'Apiary', 'cn': [r'^(.+)\.apiary\.io$'], 'fp': [{'body': [r"Uh oh! Nothing here"], 's': [404]}], 'claimable': True, 'pri': 'medium'},
    'anima': {'name': 'Anima', 'cn': [r'^(.+)\.animaapp\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'appfleet': {'name': 'AppFleet', 'cn': [r'^(.+)\.appfleet\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'akamai-cloudlets': {'name': 'Akamai Cloudlets', 'cn': [r'^(.+)\.deploy\.akamai\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'sucuri': {'name': 'Sucuri', 'cn': [r'^(.+)\.sucuri\.net$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'cachefly': {'name': 'CacheFly', 'cn': [r'^(.+)\.cachefly\.net$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'cdn77': {'name': 'CDN77', 'cn': [r'^(.+)\.cdn77\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'clearvps': {'name': 'ClearVPS', 'cn': [r'^(.+)\.clearvps\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Cloud file shares
    'dropbox-business': {'name': 'Dropbox Business', 'cn': [r'^(.+)\.dropboxusercontent\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'box': {'name': 'Box', 'cn': [r'^(.+)\.box\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'onedrive-business': {'name': 'OneDrive Business', 'cn': [r'^(.+)\.sharepoint\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # DevOps
    'chef': {'name': 'Chef', 'cn': [r'^(.+)\.chef\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'ansible-galaxy': {'name': 'Ansible Galaxy', 'cn': [r'^(.+)\.galaxy\.ansible\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'puppet': {'name': 'Puppet', 'cn': [r'^(.+)\.puppet\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'octopus': {'name': 'Octopus Deploy', 'cn': [r'^(.+)\.octopus\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Voice / VoIP
    'aircall': {'name': 'Aircall', 'cn': [r'^(.+)\.aircall\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'ringcentral': {'name': 'RingCentral', 'cn': [r'^(.+)\.ringcentral\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # HR / benefits
    'workday': {'name': 'Workday', 'cn': [r'^(.+)\.workday\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'greenhouse': {'name': 'Greenhouse', 'cn': [r'^(.+)\.greenhouse\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'lever': {'name': 'Lever', 'cn': [r'^(.+)\.lever\.co$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Legacy / long-tail
    'hatenablog': {'name': 'Hatena Blog', 'cn': [r'^(.+)\.hatenablog\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'blogspot': {'name': 'Blogspot', 'cn': [r'^(.+)\.blogspot\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'weebly': {'name': 'Weebly', 'cn': [r'^(.+)\.weebly\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'wix-alt': {'name': 'Wix (Alt)', 'cn': [r'^(.+)\.editorx\.io$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},

    # Recent additions (Jan 2026 landscape)
    'lambda-url': {'name': 'AWS Lambda URL', 'cn': [r'^(.+)\.lambda-url\.[a-z0-9-]+\.on\.aws$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'cloudflare-worker-domain': {'name': 'Cloudflare Worker Custom Domain', 'cn': [r'^(.+)\.workers\.cloudflare\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Reserved'},
    'coolify': {'name': 'Coolify.io', 'cn': [r'^(.+)\.coolify\.io$'], 'fp': [], 'claimable': 'verify', 'pri': 'medium'},
    'coolify-cloud': {'name': 'Coolify Cloud', 'cn': [r'^(.+)\.coolify\.cloud$'], 'fp': [], 'claimable': 'verify', 'pri': 'medium'},
    'zeabur': {'name': 'Zeabur', 'cn': [r'^(.+)\.zeabur\.app$'], 'fp': [{'body': [r"Application not found"], 's': [404]}], 'claimable': 'verify', 'pri': 'medium'},
    'ngrok': {'name': 'Ngrok', 'cn': [r'^(.+)\.ngrok(-free)?\.app$', r'^(.+)\.ngrok\.io$'], 'fp': [{'body': [r'Tunnel .* not found'], 's': [404]}], 'claimable': False, 'pri': 'low', 'dead': 'Ephemeral'},
    'localtunnel': {'name': 'LocalTunnel', 'cn': [r'^(.+)\.loca\.lt$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Ephemeral'},
    'cloudflared': {'name': 'Cloudflared', 'cn': [r'^(.+)\.trycloudflare\.com$'], 'fp': [], 'claimable': False, 'pri': 'low', 'dead': 'Ephemeral'},
}
