import i18n from '@/utils/locale'
import yup from '@/utils/yup'

export const schema = () => yup.object({
  status: yup.string().nullable().label(i18n.t('Enable')),
  cacert: yup.string().nullable().label(i18n.t('CA Certificate')),
  backend: yup.string().nullable().label(i18n.t('Database Host')),
  backend_port: yup.string().label(i18n.t('Database Port')).isPort(),
  encryption: yup.string().label(i18n.t('Database Encryption')),
})

export default schema

