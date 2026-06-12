import Vue from 'vue'
import VueRouter from 'vue-router'
import Home from '../views/Home.vue'
import BrokenAuthLab from '../views/BrokenAuthLab.vue'
import BolaLab from '../views/BolaLab.vue'
import CorsLab from '../views/CorsLab.vue'
import DataExposureLab from '../views/DataExposureLab.vue'
import DockerSecurityLab from '../views/DockerSecurityLab.vue'
import JwtLab from '../views/JwtLab.vue'
import NoSqlInjectionLab from '../views/NoSqlInjectionLab.vue'
import RateLimitLab from '../views/RateLimitLab.vue'
import SqliLab from '../views/SqliLab.vue'
import XssLab from '../views/XssLab.vue'
import TokenStorageLab from '../views/TokenStorageLab.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'home',
    component: Home
  },
  {
    path: '/lab/token-storage',
    name: 'token-storage-lab',
    component: TokenStorageLab,
    alias: '/labs/token-storage'
  },
  {
    path: '/lab/broken-auth',
    name: 'broken-auth-lab',
    component: BrokenAuthLab,
    alias: '/labs/broken-auth'
  },
  {
    path: '/lab/sqli',
    name: 'sqli-lab',
    component: SqliLab,
    alias: '/labs/sqli'
  },
  {
    path: '/lab/nosqli',
    name: 'nosqli-lab',
    component: NoSqlInjectionLab,
    alias: '/labs/nosqli'
  },
  {
    path: '/lab/bola',
    name: 'bola-lab',
    component: BolaLab,
    alias: '/labs/bola'
  },
  {
    path: '/lab/jwt',
    name: 'jwt-lab',
    component: JwtLab,
    alias: '/labs/jwt'
  },
  {
    path: '/lab/cors',
    name: 'cors-lab',
    component: CorsLab,
    alias: '/labs/cors'
  },
  {
    path: '/lab/exposure',
    name: 'exposure-lab',
    component: DataExposureLab,
    alias: '/labs/exposure'
  },
  {
    path: '/lab/docker-security',
    name: 'docker-security-lab',
    component: DockerSecurityLab,
    alias: '/labs/docker-security'
  },
  {
    path: '/lab/rate-limit',
    name: 'rate-limit-lab',
    component: RateLimitLab,
    alias: '/labs/rate-limit'
  },
  {
    path: '/lab/xss',
    name: 'xss-lab',
    component: XssLab,
    alias: '/labs/xss'
  }
]

const router = new VueRouter({
  mode: 'history',
  routes
})

export default router
