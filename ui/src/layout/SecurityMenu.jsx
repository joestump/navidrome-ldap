import React, { forwardRef } from 'react'
import { MenuItemLink, useTranslate } from 'react-admin'
import { MdLock } from 'react-icons/md'
import { makeStyles } from '@material-ui/core'

const useStyles = makeStyles((theme) => ({
  menuItem: {
    color: theme.palette.text.secondary,
  },
}))

const SecurityMenu = forwardRef(({ onClick, sidebarIsOpen, dense }, ref) => {
  const translate = useTranslate()
  const classes = useStyles()
  return (
    <MenuItemLink
      ref={ref}
      to="/security"
      primaryText={translate('menu.security.name')}
      leftIcon={<MdLock size={24} />}
      onClick={onClick}
      className={classes.menuItem}
      sidebarIsOpen={sidebarIsOpen}
      dense={dense}
    />
  )
})

SecurityMenu.displayName = 'SecurityMenu'

export default SecurityMenu
