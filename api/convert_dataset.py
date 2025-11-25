import pandas as pd
import os

print('🔄 Convertendo dataset...')
df = pd.read_csv('phishing_site_urls.csv')
print(f'📊 Total original: {len(df)} URLs')

df.columns = ['url', 'label']
df['label'] = df['label'].map({'bad': 1, 'good': 0})
df = df.dropna()

def fix_url(url):
    if not url.startswith(('http://', 'https://' )):
        return 'http://' + url
    return url

df['url'] = df['url'].apply(fix_url )
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

os.makedirs('data', exist_ok=True)
df.to_csv('data/dataset.csv', index=False)

print(f'✅ Convertido: {len(df)} URLs')
print(f'   Legítimas: {(df[\"label\"] == 0).sum()}')
print(f'   Phishing: {(df[\"label\"] == 1).sum()}')
