import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

import en from './locales/en.json';
import ar from './locales/ar.json';
import fr from './locales/fr.json';

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: en },
      ar: { translation: ar },
      fr: { translation: fr },
    },
    fallbackLng: 'en',
    supportedLngs: ['en', 'ar', 'fr'],
    interpolation: { escapeValue: false },
    detection: {
      order: ['localStorage', 'navigator', 'htmlTag'],
      caches: ['localStorage'],
      lookupLocalStorage: 'cs.lang',
    },
  });

// Sync <html> dir + lang on language change (RTL for Arabic).
function applyDocumentLang(lng) {
  if (typeof document === 'undefined') return;
  document.documentElement.lang = lng;
  document.documentElement.dir = lng === 'ar' ? 'rtl' : 'ltr';
}
i18n.on('languageChanged', applyDocumentLang);
applyDocumentLang(i18n.language || 'en');

export default i18n;
