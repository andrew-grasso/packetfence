
import store from '@/store'
import { createDebouncer } from 'promised-debounce'
import { ref, watch } from '@vue/composition-api'

export default (id, key, defaultValue) => {

<<<<<<< HEAD
  const preference = ref(defaultValue)
=======
  const preference = ref(undefined)
>>>>>>> daf6c1dd44... feature(admin(js)): add preference composable
  let debouncer

  store.dispatch('preferences/get', id).then(value => {
    preference.value = value[key] || defaultValue

    watch(preference, () => {
      if (!debouncer) {
        debouncer = createDebouncer()
      }
      debouncer({
        handler: () => {
          const { meta, ...currentValue } = store.state.preferences.cache[id]
          store.dispatch('preferences/set', { id, value: { ...currentValue, [key]: preference.value } })
        },
        time: 100
      })
    }, { deep: true })
  })

  return preference
}