package com.slexn.multiboard.entities.documents;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


@Data
@Document("users")
public class User implements UserDetails {
    @Id
    private String id;

    @NotBlank
    @Size(max = 20)
    @Indexed(unique = true)
    private String username;

    @NotBlank
    @Size(max = 20)
    @Indexed(unique = true)
    @Email
    private String email;

    @NotBlank
    @Size(max = 120)
    @JsonIgnore
    private String password;
    private Boolean status;
    @DocumentReference
    private Set<Role> roles = new HashSet<>();

    private List<String> workspaceIds;
    private List<String> ownedWorkspaces;
    private List<String> ownedBuilds;
    private List<String> ownedTestRuns;
    private List<String> ctcReports;

    public User(String username, String email, String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    public void addRole(Role role) {
        if (roles == null) {
            roles = new HashSet<>();
        }
        roles.add(role);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.EMPTY_LIST;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }


    public void addWorkspace(String workspaceId) {
        if (this.workspaceIds == null) {
            this.workspaceIds = new ArrayList<>();
        }
        this.workspaceIds.add(workspaceId);
    }

    public void addOwnedWorkspace(String workspaceId) {
        if (this.ownedWorkspaces == null) {
            this.ownedWorkspaces = new ArrayList<>();
        }
        this.ownedWorkspaces.add(workspaceId);
    }

    public void removeWorkspace(String workspaceId) {
        this.workspaceIds.remove(workspaceId);
    }

    public void removeOwnedWorkspace(String workspaceId) {
        this.ownedWorkspaces.remove(workspaceId);
    }

    public void addOwnedBuild(String buildId) {
        if (this.ownedBuilds == null) {
            this.ownedBuilds = new ArrayList<>();
        }
        this.ownedBuilds.add(buildId);
    }

    public void removeOwnedBuild(String buildId) {
        this.ownedBuilds.remove(buildId);
    }
    public void addCtcReport(String id){
        if (this.ctcReports == null){
            this.ctcReports = new ArrayList<>();
        }
        if (!this.ctcReports.contains(id)){
            this.ctcReports.add(id);
        }
    }
}

