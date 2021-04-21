import { BaseFormGroupTextareaUpload, BaseFormGroupTextareaUploadProps } from '@/components/new/'
import i18n from '@/utils/locale'

export const props = {
  ...BaseFormGroupTextareaUploadProps,

  // overload :accept default
  accept: {
    type: String,
    default: 'application/x-x509-ca-cert, application/vnd.apple.keynote, text/*'
  },

  // overload :tooltip default
  tooltip: {
    type: String,
    default: i18n.t('Click or drag-and-drop to upload a certificate')
  }
}

export default {
  name: 'base-form-group-certificate',
  extends: BaseFormGroupTextareaUpload,
  props
}
