import Vue from 'vue'
import CompositionApi from '@vue/composition-api'
import BootstrapVue from 'bootstrap-vue'
import i18n from '@/utils/locale'
import VueTimeago from 'vue-timeago'
import Icon from 'vue-awesome/components/Icon'
import 'vue-awesome/icons/arrow-circle-right'
import 'vue-awesome/icons/angle-double-down'
import 'vue-awesome/icons/balance-scale'
import 'vue-awesome/icons/ban'
import 'vue-awesome/icons/barcode'
import 'vue-awesome/icons/bars'
import 'vue-awesome/icons/bell'
import 'vue-awesome/icons/book'
import 'vue-awesome/icons/calendar-alt'
import 'vue-awesome/icons/calendar-check'
import 'vue-awesome/icons/caret-up'
import 'vue-awesome/icons/caret-down'
import 'vue-awesome/icons/caret-right'
import 'vue-awesome/icons/chart-bar'
import 'vue-awesome/icons/chart-line'
import 'vue-awesome/icons/chart-pie'
import 'vue-awesome/icons/check'
import 'vue-awesome/icons/check-circle'
import 'vue-awesome/icons/check-square'
import 'vue-awesome/icons/chevron-circle-right'
import 'vue-awesome/icons/chevron-circle-down'
import 'vue-awesome/icons/chevron-left'
import 'vue-awesome/icons/chevron-right'
import 'vue-awesome/icons/chevron-down'
import 'vue-awesome/icons/circle'
import 'vue-awesome/icons/circle-notch'
import 'vue-awesome/icons/clipboard-list'
import 'vue-awesome/icons/clock'
import 'vue-awesome/icons/clone'
import 'vue-awesome/icons/code'
import 'vue-awesome/icons/cog'
import 'vue-awesome/icons/cogs'
import 'vue-awesome/icons/columns'
import 'vue-awesome/icons/compress'
import 'vue-awesome/icons/copy'
import 'vue-awesome/icons/cut'
import 'vue-awesome/icons/directions'
import 'vue-awesome/icons/door-open'
import 'vue-awesome/icons/ellipsis-h'
import 'vue-awesome/icons/ellipsis-v'
import 'vue-awesome/icons/exchange-alt'
import 'vue-awesome/icons/exclamation-circle'
import 'vue-awesome/icons/exclamation-triangle'
import 'vue-awesome/icons/desktop'
import 'vue-awesome/icons/download'
import 'vue-awesome/icons/edit'
import 'vue-awesome/icons/expand'
import 'vue-awesome/icons/external-link-alt'
import 'vue-awesome/icons/eye'
import 'vue-awesome/icons/fast-backward'
import 'vue-awesome/icons/file'
import 'vue-awesome/icons/file-csv'
import 'vue-awesome/icons/file-excel'
import 'vue-awesome/icons/file-export'
import 'vue-awesome/icons/font'
import 'vue-awesome/icons/regular/file'
import 'vue-awesome/icons/fingerprint'
import 'vue-awesome/icons/regular/folder'
import 'vue-awesome/icons/regular/folder-open'
import 'vue-awesome/icons/forward'
import 'vue-awesome/icons/brands/github'
import 'vue-awesome/icons/grip-horizontal'
import 'vue-awesome/icons/grip-vertical'
import 'vue-awesome/icons/history'
import 'vue-awesome/icons/id-card'
import 'vue-awesome/icons/info-circle'
import 'vue-awesome/icons/layer-group'
import 'vue-awesome/icons/lock'
import 'vue-awesome/icons/long-arrow-alt-down'
import 'vue-awesome/icons/long-arrow-alt-right'
import 'vue-awesome/icons/magic'
import 'vue-awesome/icons/minus-circle'
import 'vue-awesome/icons/moon'
import 'vue-awesome/icons/notes-medical'
import 'vue-awesome/icons/palette'
import 'vue-awesome/icons/pause'
import 'vue-awesome/icons/pause-circle'
import 'vue-awesome/icons/phone'
import 'vue-awesome/icons/play'
import 'vue-awesome/icons/play-circle'
import 'vue-awesome/icons/plug'
import 'vue-awesome/icons/plus-circle'
import 'vue-awesome/icons/power-off'
import 'vue-awesome/icons/project-diagram'
import 'vue-awesome/icons/puzzle-piece'
import 'vue-awesome/icons/question-circle'
import 'vue-awesome/icons/regular/question-circle'
import 'vue-awesome/icons/random'
import 'vue-awesome/icons/redo'
import 'vue-awesome/icons/redo-alt'
import 'vue-awesome/icons/retweet'
import 'vue-awesome/icons/ruler-combined'
import 'vue-awesome/icons/save'
import 'vue-awesome/icons/search'
import 'vue-awesome/icons/search-minus'
import 'vue-awesome/icons/search-plus'
import 'vue-awesome/icons/server'
import 'vue-awesome/icons/shield-alt'
import 'vue-awesome/icons/sign-in-alt'
import 'vue-awesome/icons/sign-out-alt'
import 'vue-awesome/icons/sitemap'
import 'vue-awesome/icons/sort'
import 'vue-awesome/icons/sort-numeric-up-alt'
import 'vue-awesome/icons/sort-numeric-down'
import 'vue-awesome/icons/spinner'
import 'vue-awesome/icons/step-backward'
import 'vue-awesome/icons/regular/dot-circle'
import 'vue-awesome/icons/regular/times-circle'
import 'vue-awesome/icons/regular/square'
import 'vue-awesome/icons/square'
import 'vue-awesome/icons/stop'
import 'vue-awesome/icons/stop-circle'
import 'vue-awesome/icons/stopwatch'
import 'vue-awesome/icons/sun'
import 'vue-awesome/icons/sync'
import 'vue-awesome/icons/th'
import 'vue-awesome/icons/thumbtack'
import 'vue-awesome/icons/times'
import 'vue-awesome/icons/times-circle'
import 'vue-awesome/icons/toggle-on'
import 'vue-awesome/icons/toggle-off'
import 'vue-awesome/icons/tools'
import 'vue-awesome/icons/trash-alt'
import 'vue-awesome/icons/undo-alt'
import 'vue-awesome/icons/unlink'
import 'vue-awesome/icons/upload'
import 'vue-awesome/icons/user'
import 'vue-awesome/icons/user-circle'
import 'vue-awesome/icons/user-lock'
import 'vue-awesome/icons/user-plus'
import 'vue-awesome/icons/user-secret'
import 'vue-awesome/icons/wifi'
import 'vue-awesome/icons/window-maximize'

import pfIcons from '@/globals/pfIcons'
Icon.register(pfIcons)

import { createPinia, PiniaVuePlugin } from 'pinia'
import store from './store'
import router from './router'
import filters from './utils/filters'
import { pfTemplatePlugin } from './utils/plugins'
import App from './App'

import 'bootstrap-vue/dist/bootstrap-vue.css'
import 'vue2vis/dist/vue2vis.css'

// Ignore custom elements defined outside of Vue
Vue.config.ignoredElements = [
  'ip',
  'mac'
]
Vue.config.devtools = process.env.VUE_APP_DEBUG === 'true'
Vue.config.performance = process.env.VUE_APP_DEBUG === 'true'

Vue.use(VueTimeago, {
  name: 'Timeago',
  locale: undefined,
  locales: {
    'fr': require('date-fns/locale/fr')
  }
})
Vue.component('icon', Icon)
Vue.use(BootstrapVue)
Vue.use(CompositionApi)
Vue.use(pfTemplatePlugin)
Vue.use(PiniaVuePlugin)
const pinia = createPinia()

// Register global filters
for (const filter of Object.keys(filters)) {
  Vue.filter(filter, filters[filter])
}

const app = new Vue({
  render: h => h(App),
  router,
  store,
  i18n,
  pinia,
}).$mount('#app')

if (process.env.VUE_APP_DEBUG === 'true') {
  // Configure Vue.js devtools (https://github.com/vuejs/vue-devtools)
  window.__VUE_DEVTOOLS_GLOBAL_HOOK__.Vue = app.constructor
}
