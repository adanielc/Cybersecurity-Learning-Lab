import Vue from 'vue'
import Vuetify from 'vuetify'
import 'vuetify/dist/vuetify.min.css'
import '@mdi/font/css/materialdesignicons.css'

Vue.use(Vuetify)

export default new Vuetify({
  icons: {
    iconfont: 'mdi'
  },
  theme: {
    options: {
      customProperties: true
    },
    themes: {
      light: {
        primary: '#B20C36',
        primaryDark: '#7E0A26',
        secondary: '#575756',
        accent: '#9D9D9C',
        error: '#C62828',
        warning: '#F9A825',
        info: '#B20C36',
        success: '#2E7D32',
        background: '#F5F7FA',
        surface: '#FFFFFF'
      }
    }
  }
})
