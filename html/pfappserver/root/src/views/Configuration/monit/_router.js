import store from '@/store'
import BasesStoreModule from '../bases/_store'

const TheTabs = () => import(/* webpackChunkName: "Configuration" */ '../_components/TheTabsMain')

export const beforeEnter = (to, from, next = () => {}) => {
  if (!store.state.$_bases) {
    store.registerModule('$_bases', BasesStoreModule)
  }
  next()
}

const can = () => !store.getters['system/isSaas']

export default [
  {
    path: 'monit',
    name: 'monit',
    component: TheTabs,
    meta: {
      can
    },
    props: () => ({ tab: 'monit' }),
    beforeEnter
  }
]
